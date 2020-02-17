#ifndef __LOADER_H
#define __LOADER_H

#include <assert.h>
#include "uthash.h"

/*
** Arguments x and y are both integers. Argument y must be a power of 2.
** Round x up to the nearest integer multiple of y. For example:
**     ROUNDUP(0,  8) ->  0
**     ROUNDUP(13, 8) -> 16
**     ROUNDUP(32, 8) -> 32
*/
#define ROUNDUP(x,y)     (((x)+y-1)&~(y-1))

/* Instruction patching */
typedef struct{
	uint8_t mov;
	uint8_t eax;
	uint64_t address;
	uint8_t jmp0;
	uint8_t jmp1;
	uint8_t noop0;
	uint8_t noop1;
	uint8_t noop2;
	uint8_t noop3;
}__attribute__((__packed__)) jump_patch_t;

/* Runtime "/proc/<pid>/maps" info */
typedef struct {
	uint64_t code_start;
	uint64_t code_end;
	uint64_t rodata_start;
	uint64_t rodata_end;
	uint64_t data_start;
	uint64_t data_end;
} proc_info_t;

/* Binary section info from "readelf -SW <binary>" */
typedef struct {
	uint64_t code_start;
	uint64_t code_size;
	uint64_t data_start;
	uint64_t data_size;
	uint64_t bss_start;
	uint64_t bss_size;
	uint64_t plt_start;
	uint64_t plt_size;
	uint64_t gotplt_start;
	uint64_t gotplt_size;
} binary_info_t;

/* Hash table: name (key) --> offset */
typedef struct {
	char name[128];		/* key: function name */
	uint64_t offset;
	UT_hash_handle hh;	/* make this struct hashable */
} hash_table_t;

/* Reverse hash table: offset (key) --> name */
typedef struct {
	int offset;			/* key: function offset */
	char name[128];
	UT_hash_handle hh;	/* make this struct hashable */
} rev_hash_table_t;

extern hash_table_t *g_ht_fun;
extern rev_hash_table_t *g_ht_offset;

/* function declaration */
int init_loader();
int read_proc(const char *bin_name, proc_info_t *pinfo);
void read_gotplt();
void patch_plt();
void copy_data_bss();
void update_pointers_self();
void update_heap_pointers_self();
void update_data_pointers_self();
void update_vma_permission();
static int read_binary_info(binary_info_t *binfo);
static void *dup_proc(proc_info_t *pinfo, binary_info_t *binfo);
static int update_code_pointers(proc_info_t *pinfo, binary_info_t *binfo, int64_t delta);
static int update_heap_code_pointers(uint64_t base, int64_t delta);

#endif
