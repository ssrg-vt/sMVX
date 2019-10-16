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

int _thread_trampoline(void *p)
{
	printf("%s: hello. thread id %ld.\n", __func__, syscall(SYS_gettid));
	return 0;
}

int lmvx_init()
{
	int i = 0;
	FILE *conf_tbl = fopen(CONF_TAB_ADDR_FILE, "r");

	// initial the conf file
	if (conf_tbl == NULL) {
		log_error("Failed to open CONF file for indirection table.");
		exit(EXIT_FAILURE);
	}
	fscanf(conf_tbl, "%p", &ind_table);

	// initial stack
	stack = malloc(STACK_SIZE);
	if (stack == NULL) {
		perror("malloc failed.");
		exit(EXIT_FAILURE);
	}
	stackTop = stack + STACK_SIZE;

	// init ind_table
	log_info("ind_table %p.", ind_table);
	while (ind_table[i].func_name != NULL) {
		log_info("--> [%2d].name %s: %p", i, ind_table[i].func_name, ind_table[i].func_addr);
		i++;
	}
	log_info("test -- check the first 8 bytes of %s: 0x%lx",
			ind_table[0].func_name, *(long *)(ind_table[0].func_addr));

	return 0;
}

void lmvx_start(const char *func_name, int n, ...)
{
	va_list params;
	unsigned long param;

	va_start(params, n);
	while (n > 0) {
		param = va_arg(params, u64);
		log_info("n: %d, val: %lu -- 0x%lx", n, param, param);
		n--;
	}
	va_end(params);

	log_info("%s: hello. thread id %ld.", __func__, syscall(SYS_gettid));
	clone(_thread_trampoline, stackTop, CLONE_VM, NULL);
}

void lmvx_end()
{
	log_info("%s: goodbye. thread id %ld.", __func__, syscall(SYS_gettid));
}
