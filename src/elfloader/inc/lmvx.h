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

/**
 * external function table entry <name,pointer>
 * */
//typedef struct ext_func_tbl_entry {
//	char *func_name;
//	void *func_addr;
//	int flag;
//} tbl_entry_t;

//tbl_entry_t *ind_table;

typedef struct {
	char *name;
	uint32_t offset;
	uint32_t flag;
} func_desc_t;

int lmvx_init(void);
void lmvx_start(const char *func_name, int n, ...);
void lmvx_end(void);

#if 0
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
#endif

#endif
