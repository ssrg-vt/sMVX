#ifndef __MONITOR_TRAMPOLINE_H__
#define __MONITOR_TRAMPOLINE_H__
#include <stdint.h>

typedef struct {
	uint64_t code_start;
	uint64_t code_end;
	uint64_t rodata_start;
	uint64_t rodata_end;
	uint64_t data_start;
	uint64_t data_end;
} proc_info_t;

int read_proc(const char *bin_name, proc_info_t *pinfo);
void store_original_functions();


#endif
