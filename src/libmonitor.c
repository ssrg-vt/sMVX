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
#include "lmvx.h"

#define MONITOR_SHARED_MEM_NAME "/monitor-memory"
#define MONITOR_SYNC_MEM_NAME "/monitor-sync-memory"

/* PID of the child variant */
unsigned long mvx_child_pid = 0;

/* PID of the parent variant */
unsigned long mvx_parent_pid = 0;

char *stack;
char *stackTop;

/* Shared memory */
extern struct call_data* calldata_ptr;
extern struct sync_data* syncdata_ptr;

void __attribute__ ((constructor)) init_tramp(int argc, char** argv, char** env)
{
	/*Call this guy all the time first */
	store_original_functions();

	/* Load elf binary */
	init_loader();

	mvx_parent_pid = getpid();

	setup_ipc();

	/* initialize the thread stack */
	stack = malloc(STACK_SIZE);
	if (stack == NULL) {
		log_error("malloc failed.");
		exit(EXIT_FAILURE);
	}
	stackTop = stack + STACK_SIZE;

	log_info("Trampoline library instantiated");
}

void associate_all_pkeys()
{
	unsigned long pkey;
	proc_info_t monitor_info, libc_info;
	DEACTIVATE();
	/* Allocate pkey */
	pkey = syscall(SYS_pkey_alloc, 0, 0);

	log_debug("Pkey allocated is: %lu", pkey);
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

void set_mvx_active()
{
	/* Set flag that mvx is active */
	calldata_ptr->mvx_active = true;
}

void clear_mvx_active()
{
	/* clear flag that mvx is active */
	calldata_ptr->mvx_active = false;
}

void setup_ipc()
{
	pthread_mutexattr_t attrmutex;
	pthread_condattr_t attrcond;

	int fd_shm;
	int fd_shm_sync;

	/* Create shared memory */
	if ((fd_shm = shm_open (MONITOR_SHARED_MEM_NAME, O_RDWR | O_CREAT, 0660)) == -1){
		log_error("Failed to create semaphore");
		assert(false);
	}

	if (ftruncate (fd_shm, sizeof (struct call_data)) == -1){
		log_error("Failed to ftruncate");
		assert(false);
	}

	if ((calldata_ptr = mmap (NULL, sizeof (struct call_data), PROT_READ | PROT_WRITE, MAP_SHARED,
	        fd_shm, 0)) == MAP_FAILED){
		log_error("Failed to mmap");
		assert(false);
	}

	/* Create synchronization shared memory */
	if ((fd_shm_sync = shm_open (MONITOR_SYNC_MEM_NAME, O_RDWR | O_CREAT, 0660)) == -1){
		log_error("Failed to create semaphore");
		assert(false);
	}

	if (ftruncate (fd_shm_sync, sizeof (struct sync_data)) == -1){
		log_error("Failed to ftruncate");
		assert(false);
	}

	if ((syncdata_ptr = mmap (NULL, sizeof (struct sync_data), PROT_READ | PROT_WRITE, MAP_SHARED,
	        fd_shm_sync, 0)) == MAP_FAILED){
		log_error("Failed to mmap");
		assert(false);
	}

	pthread_mutexattr_init(&attrmutex);
	pthread_mutexattr_setpshared(&attrmutex, PTHREAD_PROCESS_SHARED);

	pthread_condattr_init(&attrcond);
	pthread_condattr_setpshared(&attrcond, PTHREAD_PROCESS_SHARED);

	pthread_mutex_init(&(syncdata_ptr->monitor_mutex), &attrmutex);
	pthread_cond_init(&(syncdata_ptr->master_done), &attrcond);
	pthread_cond_init(&(syncdata_ptr->follower_done), &attrcond);

	/* Initialize calldata */
	calldata_ptr->ready_for_check = false;
	calldata_ptr->check_done = false;
	calldata_ptr->mvx_active = false;
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

