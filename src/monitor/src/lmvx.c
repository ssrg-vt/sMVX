/**
 * This is the real implementation of lmvx_init()/lmvx_start()/lmvx_end().
 * Monitor code/data will be protected by randomization, XoM and MPK.
 * */
#define _GNU_SOURCE
#include <stdarg.h>			// u64
#include <stdlib.h>			// exit()/EXIT_FAILUR
#include <sched.h>			// CLONE_FILES
#include <signal.h>			// SIGCHILD
#include <sys/types.h>
#include <sys/wait.h>		// wait

#include "lmvx.h"
#include "libmonitor.h"
#include "pkey.h"			// DEACTIVATE()/ACTIVATE()

/* Global memory to store thread function call arguments. */
shim_args_t args;

/* Stack for variant thread. */
char *stack = NULL;
char *stackTop = NULL;

//extern func_desc_t g_func[];
extern void *new_text_base;

/* A global variable used for executing critical function once. */
int flag_lmvx = 1;

static int _lmvx_thread_shim(void *p)
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
 * Return the offset of the function with function name (symbol) as param.
 * */
static u64 find_symbol_offset(const char *symbol)
{
	DEACTIVATE();
	hash_table_t *entry = NULL;

	assert(symbol != NULL);

	HASH_FIND_STR(g_ht_fun, symbol, entry);
	if (entry == NULL) {
		log_error("Cannot find symbol %s", symbol);
		return 0;
	}
	else {
		log_info("Function name %s, offset 0x%lx", symbol, entry->offset);
		return entry->offset;
	}
}

/**
 * lMVX library initialization.
 * */
int lmvx_init(void)
{
	DEACTIVATE();
	int i = 0;

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
	u64 param, offset;
	u64 *p = (u64 *)&args;	/* jmp addr, n args, arg0, ..., arg5 */
	int i = 0, ret = 0;

	assert(argc <= 6);		// TODO: handle functions with 6+ params
	DEACTIVATE();

	/* find function offset from hash table. */
	offset = find_symbol_offset(func_name);
	assert(offset != 0);
	DEACTIVATE();

	/* prepare "shim_args_t args" */
	*p = (u64)new_text_base + offset;
	*(p + 1) = argc;
	va_start(params, argc);
	while (i < argc) {
		param = va_arg(params, u64);
		*(p + 2 + i) = param;
		i++;
	}
	va_end(params);

	log_debug("fun name %s. offset %x. jmp to 0x%lx", func_name, offset, *p);
	DEACTIVATE();

	/* Synchronize over the bss and data */
	copy_data_bss();

	/* update code pointers */
	update_pointers_self();

	log_trace("%s: pid %d. child jmp to 0x%lx", __func__, getpid(), *p);
	DEACTIVATE();

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
