#ifndef _LMVX_H
#define _LMVX_H

#include <stddef.h>

#define STACK_SIZE	(1024*1024)
#define TAB_SIZE	16

// external function table entry <name,pointer>
typedef struct ext_func_tbl_entry {
	char *func_name;
	void *p;
} tbl_entry_t;

tbl_entry_t ind_table[TAB_SIZE];

int lmvx_init();
void lmvx_start(const char *func_name, ...);
void lmvx_end();

#endif
