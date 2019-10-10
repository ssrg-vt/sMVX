#ifndef __LMVX_H
#define __LMVX_H

#define _GNU_SOURCE

#include <stdarg.h>
#include <stdio.h>
#include <linux/sched.h>

#define STACK_SIZE	(1024*1024)

char *stack = NULL;
char *stackTop = NULL;

void fun()
{
	printf("%s: hello. thread id %ld.\n", __func__, syscall(SYS_gettid));
}

int lmvx_init()
{
	stack = malloc(STACK_SIZE);
	if (stack == NULL) {
		perror("malloc failed.");
		exit(EXIT_FAILURE);
	}
	stackTop = stack + STACK_SIZE;

	return 0;
}

void lmvx_start(const char *func_name, ...)
{
	va_list params;

	printf("%s: hello. thread id %ld.\n", __func__, syscall(SYS_gettid));
	clone(fun, stackTop, CLONE_VM, NULL);
}

void lmvx_end()
{
	printf("%s: goodbye. thread id %ld.\n", __func__, syscall(SYS_gettid));
}

#endif
