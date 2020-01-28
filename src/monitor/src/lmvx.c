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
