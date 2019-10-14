#ifndef _LMVX_H
#define _LMVX_H

#include <stddef.h>
//#include <threads.h>		// TLS: thread local storage

#define STACK_SIZE	(1024*1024)
#define TAB_SIZE	16
#define CONF_TAB_ADDR_FILE		"conf/tab_addr.conf"

typedef unsigned long		u64;

// external function table entry <name,pointer>
typedef struct ext_func_tbl_entry {
	char *func_name;
	void *func_addr;
} tbl_entry_t;

//thread_local tbl_entry_t *ind_table;
tbl_entry_t *ind_table;

int lmvx_init();
void lmvx_start(const char *func_name, int n, ...);
void lmvx_end();

#endif
