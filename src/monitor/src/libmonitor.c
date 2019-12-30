#define _GNU_SOURCE
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sched.h>
#include <errno.h>
#include <sys/syscall.h>
#include <stdarg.h>
#include <stddef.h>
#include <semaphore.h>
#include <stdbool.h>
#include <pthread.h>
#include <stdlib.h>

/* Local headers */
#include <debug.h>
#include <config.h>
#include <libmonitor.h>
#include <pkey.h>
#include <syscall_blocking.h>
#include <loader.h>
#include <ipc.h>

#define MONITOR_SHARED_MEM_NAME "/monitor-memory"

bool mvx_active = false;

/* PID of the child variant */
unsigned long mvx_child_pid = 0;

/* PID of the parent variant */
unsigned long mvx_parent_pid = 0;

/* Shared memory */
extern struct call_data* calldata_ptr;

extern pthread_mutex_t monitor_mutex;
extern pthread_cond_t master_done;

void __attribute__ ((constructor)) init_tramp(int argc, char** argv, char** env)
{
	/*Call this guy all the time first */
	store_original_functions();

	/* Load elf binary */
	init_loader();

	mvx_parent_pid = getpid();

	setup_ipc();
	log_info("Trampoline library instantiated\n");
}

void associate_all_pkeys()
{
	unsigned long pkey;
	proc_info_t monitor_info, libc_info;
	DEACTIVATE();
	/* Allocate pkey */
	pkey = syscall(SYS_pkey_alloc, 0, 0);

	/* Set flag that mvx is active */
	mvx_active = true;

	/* Associate keys with both the monitor and libc */
	read_proc("libmonitor", &monitor_info);
	read_proc("libc", &libc_info);

	/* Associate pages of the libraries with the allocated pkey */
	associate_pkey_library(&libc_info, pkey);
	associate_pkey_library(&monitor_info, pkey);
	DEACTIVATE();
}

void store_child_pid(unsigned long pid)
{
	mvx_child_pid = pid;
}

void setup_ipc()
{
	pthread_mutexattr_t attrmutex;
	pthread_condattr_t attrcond;

	int fd_shm;

	pthread_mutexattr_init(&attrmutex);
	pthread_mutexattr_setpshared(&attrmutex, PTHREAD_PROCESS_SHARED);

	pthread_condattr_init(&attrcond);
	pthread_condattr_setpshared(&attrcond, PTHREAD_PROCESS_SHARED);

	pthread_mutex_init(&monitor_mutex, &attrmutex);
	pthread_cond_init(&master_done, &attrcond);

	/* Create shared memory */
	if ((fd_shm = shm_open (MONITOR_SHARED_MEM_NAME, O_RDWR | O_CREAT, 0660)) == -1){
		log_error("Failed to create semaphore\n");
		assert(false);
	}

	if (ftruncate (fd_shm, sizeof (struct call_data)) == -1){
		log_error("Failed to ftruncate\n");
		assert(false);
	}

	if ((calldata_ptr = mmap (NULL, sizeof (struct call_data), PROT_READ | PROT_WRITE, MAP_SHARED,
	        fd_shm, 0)) == MAP_FAILED){
		log_error("Failed to mmap\n");
		assert(false);
	}

	/* Initialize calldata */
	calldata_ptr->ready_for_check = false;
}

bool is_parent()
{
	bool retval = false;
	int pid = getpid();
	if (pid == mvx_parent_pid)
		retval = true;
	return retval;
}

bool is_child()
{
	bool retval = false;
	int pid = getpid();
	if (pid == mvx_child_pid)
		retval = true;
	return retval;
}
