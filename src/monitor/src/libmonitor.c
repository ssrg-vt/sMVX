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
	log_info("Trampoline library instantiated\n");
}

void associate_all_pkeys()
{
	unsigned long pkey;
	proc_info_t monitor_info, libc_info;
	DEACTIVATE();
	/* Allocate pkey */
	pkey = syscall(SYS_pkey_alloc, 0, 0);

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

	/* Create synchronization shared memory */
	if ((fd_shm_sync = shm_open (MONITOR_SYNC_MEM_NAME, O_RDWR | O_CREAT, 0660)) == -1){
		log_error("Failed to create semaphore\n");
		assert(false);
	}

	if (ftruncate (fd_shm_sync, sizeof (struct sync_data)) == -1){
		log_error("Failed to ftruncate\n");
		assert(false);
	}

	if ((syncdata_ptr = mmap (NULL, sizeof (struct sync_data), PROT_READ | PROT_WRITE, MAP_SHARED,
	        fd_shm_sync, 0)) == MAP_FAILED){
		log_error("Failed to mmap\n");
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

/**
 * The following code are originally from "lib/liblmvx.c".
 * They are the real implementation of lMVX_init/start/end.
 * Monitor code/data will be protected by randomization/XoM/MPK.
 * */
/* Global memory to store thread function call arguments. */
shim_args_t args;

/* Stack for variant thread. */
char *stack = NULL;
char *stackTop = NULL;

extern func_desc_t g_func[];
extern void *new_text_base;

/* A global variable used for executing critical function once. */
int flag_lmvx = 1;

int _lmvx_thread_shim(void *p)
{
	DEACTIVATE(); /* Deactivate pkey for the other process */
	store_child_pid(getpid());
	log_trace("%s: trampoline to child. pid %d. jmp 0x%lx", __func__, getpid(), args.jump_addr);
	DEACTIVATE(); /* Deactivate pkey for the other process */
	ACTIVATE();

	switch (args.num_args) {
		case 0:
			goto _0; break;
		case 1:
			goto _1; break;
		case 2:
			goto _2; break;
		case 3:
			goto _3; break;
		case 4:
			goto _4; break;
		case 5:
			goto _5; break;
		case 6:
			goto _6; break;
	}

_6:
	__asm__ __volatile__("mov %0, %%r9"::"g"(args.arg5));
_5:
	__asm__ __volatile__("mov %0, %%r8"::"g"(args.arg4));
_4:
	__asm__ __volatile__("mov %0, %%rcx"::"g"(args.arg3));
_3:
	__asm__ __volatile__("mov %0, %%rdx"::"g"(args.arg2));
_2:
	__asm__ __volatile__("mov %0, %%rsi"::"g"(args.arg1));
_1:
	__asm__ __volatile__("mov %0, %%rdi"::"g"(args.arg0));
_0:
	__asm__ __volatile__("call *%0"::"g"(args.jump_addr));

	return 0;
}

/**
 * Return the index of the func_desc_t table with a symbol as input.
 * */
int find_symbol_addr(const char *symbol, func_desc_t *ind_tbl)
{
	DEACTIVATE();
	int i;
	func_desc_t *entry;

	assert(symbol != NULL);
	for (i = 0; i < TAB_SIZE; i++) {
		entry = ind_tbl + i;
		//log_trace("[%2d]: %s|%s, %x, %x.", i, entry->name, symbol,
		//		entry->offset, entry->flag);
		if (entry->name == NULL) break;
		if (!strcmp(symbol, entry->name))
			return i;
	}
	//ACTIVATE();
	return -1;
}

/**
 * lMVX library initialization.
 * */
int lmvx_init(void)
{
	DEACTIVATE();
	int i = 0;

	// just some debug info. TODO: remove them
	log_debug("%s: g_func %p. new_text_base %p", __func__, g_func, new_text_base);
	while (g_func[i].name != NULL) {
		log_info("--> [%2d].name %s: %x. flag %d", i, g_func[i].name,
				g_func[i].offset, g_func[i].flag);
		i++;
	}
	log_debug("test -- check the first 8 bytes of %s: 0x%x",
			g_func[0].name, (g_func[0].offset));

	/* initialize the thread stack */
	stack = malloc(STACK_SIZE);
	if (stack == NULL) {
		log_error("malloc failed.");
		exit(EXIT_FAILURE);
	}
	stackTop = stack + STACK_SIZE;

	associate_all_pkeys();
	return 0;
}

/**
 * lMVX spawns a variant thread
 * */
void lmvx_start(const char *func_name, int argc, ...)
{
	DEACTIVATE();
	va_list params;
	u64 param;
	u64 *p = (u64 *)&args;
	int i = 0, idx;
	int ret = 0;

	assert(argc <= 6);		// TODO: handle functions with 6+ params
	DEACTIVATE();

	idx = (u64)find_symbol_addr(func_name, g_func);
	DEACTIVATE();
	*p = (u64)new_text_base + g_func[idx].offset;
	log_debug("fun name %s. idx %d, off %x. 0x%lx", func_name,
			idx, g_func[idx].offset, *p);
	DEACTIVATE();
	*(p + 1) = argc;
	va_start(params, argc);
	while (i < argc) {
		param = va_arg(params, u64);
		*(p + 2 + i) = param;
		i++;
	}
	va_end(params);

	DEACTIVATE();
	log_trace("%s: pid %d. child jmp to 0x%lx", __func__, getpid(), *p);
	DEACTIVATE();

	/* Synchronize over the bss and data */
	copy_data_bss();

	flag_lmvx = 0;
	set_mvx_active();
	// different address space, share files
	ret = clone(_lmvx_thread_shim, stackTop, CLONE_FILES | SIGCHLD, (void *)p);
	DEACTIVATE();
	flag_lmvx = 1;
	log_info("clone ret (child pid) %d", ret);
	ACTIVATE();
}

/**
 * lMVX finishes the variant thread
 * */
void lmvx_end(void)
{
	DEACTIVATE();
	int status;

	if (wait(&status) == -1) {
		exit(EXIT_FAILURE);
	}

	clear_mvx_active();
	log_trace("%s: finish lmvx region. status %d", __func__, status);
	DEACTIVATE();

	ACTIVATE();
}
