#ifndef _LMVX_H
#define _LMVX_H

#include <stddef.h>
#include <stdint.h>

#define STACK_SIZE	(1024*1024)
#define TAB_SIZE	16
#define CONF_TAB_ADDR_FILE		"conf/tab_addr.conf"

typedef unsigned long		u64;

typedef struct _shim_args {
	u64 jump_addr;
	u64 num_args;	// unify memory size of each element

	u64 arg0;
	u64 arg1;
	u64 arg2;
	u64 arg3;
	u64 arg4;
	u64 arg5;
} shim_args_t;

extern int flag_lmvx;

int lmvx_init(void);
void lmvx_start(const char *func_name, int n, ...);
void lmvx_end(void);

#endif
