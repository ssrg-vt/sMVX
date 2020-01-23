#ifndef __LOADER_H
#define __LOADER_H

#include <elf.h>
#include <assert.h>
#include <log.h>

typedef struct {
	uint64_t code_start;
	uint64_t code_end;
	uint64_t rodata_start;
	uint64_t rodata_end;
	uint64_t data_start;
	uint64_t data_end;
} proc_info_t;

typedef struct {
	uint64_t code_start;
	uint64_t code_size;
	uint64_t data_start;
	uint64_t data_size;
	uint64_t bss_start;
	uint64_t bss_size;
} binary_info_t;

typedef struct {
	char *name;
	uint32_t offset;
	uint32_t flag;
} func_desc_t;

extern int g_func_num;

int init_loader();
int init_conf(const char *conf_filename, func_desc_t *func);
int read_proc(const char *bin_name, proc_info_t *pinfo);
int read_binary_info(binary_info_t *binfo);
void *dup_proc(proc_info_t *pinfo);
int rewrite_insn(proc_info_t *pinfo, func_desc_t *func);

#endif
