#define _GNU_SOURCE

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sched.h>
//#include <linux/sched.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/wait.h>	// wait()

#include "../inc/lmvx.h"
#include "../inc/log.h"		// log functions
#include "../inc/env.h"

char *stack = NULL;
char *stackTop = NULL;

static func_desc_t *g_func = NULL;
static void *g_base = NULL;

int flag_lmvx = 0;

/*
 * Global memory to store thread function call arguments
 * */
shim_args_t args;

int _lmvx_thread_shim(void *p)
{
	log_info("%s: trampoline to child. pid %d. jmp 0x%lx", __func__, getpid(), args.jump_addr);

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

int find_symbol_addr(const char *symbol, func_desc_t *ind_tbl)
{
	int i;
	func_desc_t *entry;

	for (i = 0; i < TAB_SIZE; i++) {
		entry = ind_tbl + i;
		log_debug("[%2d]: %s|%s, %x, %x. %d", i, entry->name, symbol,
				entry->offset, entry->flag, strcmp(entry->name, symbol));
		if (entry->name == NULL) break;
		if (!strcmp(symbol, entry->name))
			return i;
	}
	return -1;
}

/**
 * lMVX library initialization
 * */
int lmvx_init()
{
	int i = 0;
	init_env();

	// load the conf file, read g_func base addr
	FILE *conf_tbl = fopen(CONF_TAB_ADDR_FILE, "r");
	if (conf_tbl == NULL) {
		log_info("No CONF file for indirection table. vanilla mode!");
		flag_lmvx = 0;
		return 1;
	}

	// otherwise, enable lmvx mode.
	flag_lmvx = 1;

	fscanf(conf_tbl, "%p %p", &g_func, &g_base);
	log_debug("g_func %p. g_base %p", g_func, g_base);
	fclose(conf_tbl);
	remove(CONF_TAB_ADDR_FILE);	// remove the tmp conf file. TODO: vulnerable

	// initialize the g_func
	while (g_func[i].name != NULL) {
		log_debug("--> [%2d].name %s: %x. flag %d", i, g_func[i].name,
				g_func[i].offset, g_func[i].flag);
		i++;
	}
	log_debug("test -- check the first 8 bytes of %s: 0x%x",
			g_func[0].name, (g_func[0].offset));

	// initialize the thread stack
	stack = malloc(STACK_SIZE);
	if (stack == NULL) {
		log_error("malloc failed.");
		exit(EXIT_FAILURE);
	}
	stackTop = stack + STACK_SIZE;

	return 0;
}

/**
 * lMVX spawns a variant thread
 * */
void lmvx_start(const char *func_name, int n, ...)
{
	va_list params;
	u64 param;
	u64 *p = (u64 *)&args;
	int i = 0, idx;

	if (!flag_lmvx) return;

	assert(n <= 6);		// TODO: handle functions with 6+ params

	log_debug("name %s", func_name);
	idx = (u64)find_symbol_addr(func_name, g_func);
	*p = (u64)g_base + g_func[idx].offset;
	log_debug("idx %d, off %x. 0x%lx", idx, g_func[idx].offset, *p);
	*(p + 1) = n;
	va_start(params, n);
	while (i < n) {
		param = va_arg(params, u64);
		*(p + 2 + i) = param;
//		log_info("%s: n %d, i %d. val: %lu -- 0x%lx", func_name, n, i, param, param);
		i++;
	}
	va_end(params);

	log_info("%s: pid %d. child jmp to 0x%lx", __func__, getpid(), *p);
	//clone(_lmvx_thread_shim, stackTop, CLONE_VM, (void *)p);	// p & c share same space
	// different address space, share files
	clone(_lmvx_thread_shim, stackTop, CLONE_FILES | SIGCHLD, (void *)p);
}

/**
 * lMVX finishes the variant thread
 * */
void lmvx_end()
{
	int status;

	if (!flag_lmvx) return;

	log_info("%s: wait child pid %d.", __func__, getpid());

	if (wait(&status) == -1) {
		log_error("Wait for child error. errno %d (%s)", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}
	log_info("parent exits\n");
}
