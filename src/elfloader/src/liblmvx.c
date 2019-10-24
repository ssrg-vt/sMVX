#define _GNU_SOURCE

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sched.h>
#include <linux/sched.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/wait.h>	// wait()

#include "../inc/lmvx.h"
#include "../inc/log.h"		// log functions

char *stack = NULL;
char *stackTop = NULL;

/*
 * Global memory to store thread function call arguments
 * */
shim_args_t args;

int _lmvx_thread_shim(void *p)
{
	printf("%s: hello. thread id %ld. pid %d\n", __func__, syscall(SYS_gettid), getpid());
	//printf("%p. num %lu\n", p, ((shim_args_t *)p)->num_args);
	printf("%p. num %lu\n", (void *)&args, args.num_args);

	switch (args.num_args) {
		case 0:
			goto _0;
			break;
		case 1:
			goto _1;
			break;
		case 2:
			goto _2;
			break;
		case 3:
			goto _3;
			break;
		case 4:
			goto _4;
			break;
		case 5:
			goto _5;
			break;
		case 6:
			goto _6;
			break;
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
//	__asm__ __volatile__("jmp *%0"::"g"(args.jump_addr));
	__asm__ __volatile__("call *%0"::"g"(args.jump_addr));
//	while(1) usleep(5000);

	return 0;
}

void *find_symbol_addr(const char *symbol, tbl_entry_t *ind_tbl)
{
	int i;
	tbl_entry_t *entry;
	for (i = 0; i < TAB_SIZE; i++) {
		entry = ind_tbl + i;
		if (entry->func_name == NULL) break;
		if (strcmp(symbol, entry->func_name) == 0)
			return entry->func_addr;
	}
	return NULL;
}

/**
 * lMVX library initialization
 * */
int lmvx_init()
{
	int i = 0;

	// load the conf file, read ind_table base addr
	FILE *conf_tbl = fopen(CONF_TAB_ADDR_FILE, "r");
	if (conf_tbl == NULL) {
		log_error("Failed to open CONF file for indirection table.");
		//exit(EXIT_FAILURE);
		return 1;
	}
	fscanf(conf_tbl, "%p", &ind_table);

	// initialize the ind_table
	log_info("ind_table %p.", ind_table);
	while (ind_table[i].func_name != NULL) {
		log_info("--> [%2d].name %s: %p", i, ind_table[i].func_name, ind_table[i].func_addr);
		i++;
	}
	log_info("test -- check the first 8 bytes of %s: 0x%lx",
			ind_table[0].func_name, *(long *)(ind_table[0].func_addr));

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
	int i = 0;

	assert(n <= 6);		// TODO: handle functions with 6+ params

	*p = (u64)find_symbol_addr(func_name, ind_table);
	*(p + 1) = n;
	va_start(params, n);
	while (i < n) {
		param = va_arg(params, u64);
		*(p + 2 + i) = param;
//		log_info("%s: n %d, i %d. val: %lu -- 0x%lx", func_name, n, i, param, param);
		i++;
	}
	va_end(params);

	log_info("%s: hello. thread id %ld.", __func__, syscall(SYS_gettid));
	//clone(_lmvx_thread_shim, stackTop, CLONE_VM, (void *)p);	// p & c share same space
	clone(_lmvx_thread_shim, stackTop, CLONE_FILES | SIGCHLD, (void *)p);	// different space, share files
}

/**
 * lMVX finishes the variant thread
 * */
void lmvx_end()
{
	int status;
	log_info("%s: goodbye. thread id %ld.", __func__, syscall(SYS_gettid));
	if (wait(&status) == -1) {
		log_error("Wait for child error. errno %d (%s)", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}
	log_info("Parent exits");
}
