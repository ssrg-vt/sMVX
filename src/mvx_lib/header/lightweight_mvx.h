#ifndef __LIGHTWEIGHT_MVX__
#define __LIGHTWEIGHT_MVX__
#include <stdint.h>

void mvx_start_hook(const char* );
void mvx_end_hook(const char* );
void test_function();

struct shim_arguments
{
	uint64_t jump_addr;
	size_t num_args;
	uint64_t arg0;
	uint64_t arg1;
	uint64_t arg2;
	uint64_t arg3;
	uint64_t arg4;
	uint64_t arg5;
};


#endif
