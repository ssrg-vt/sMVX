#ifndef _LMVX_H
#define _LMVX_H

#include <stddef.h>

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

/**
 * external function table entry <name,pointer>
 * */
typedef struct ext_func_tbl_entry {
	char *func_name;
	void *func_addr;
} tbl_entry_t;

tbl_entry_t *ind_table;

int lmvx_init(void);
void lmvx_start(const char *func_name, int n, ...);
void lmvx_end(void);

#endif
