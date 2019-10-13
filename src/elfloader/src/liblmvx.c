#define _GNU_SOURCE

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sched.h>
#include <linux/sched.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "../inc/lmvx.h"
#include "../inc/log.h"		// log functions

char *stack = NULL;
char *stackTop = NULL;

int fun(void *p)
{
	printf("%s: hello. thread id %ld.\n", __func__, syscall(SYS_gettid));
	return 0;
}

int lmvx_init()
{
	// initial stack
	stack = malloc(STACK_SIZE);
	if (stack == NULL) {
		perror("malloc failed.");
		exit(EXIT_FAILURE);
	}
	stackTop = stack + STACK_SIZE;

	// init ind_table
	ind_table[0].func_name = "print_hello";

	log_info("ind_table %p, [0].p %p.", ind_table, &(ind_table[0].p));

	return 0;
}

void lmvx_start(const char *func_name, ...)
{
//	va_list params;

	log_info("%s: hello. thread id %ld.", __func__, syscall(SYS_gettid));
	clone(fun, stackTop, CLONE_VM, NULL);
}

void lmvx_end()
{
	log_info("%s: goodbye. thread id %ld.", __func__, syscall(SYS_gettid));
}
