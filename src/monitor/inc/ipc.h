#ifndef __IPC_H__
#define __IPC_H__

#include <stdint.h>
#include <stdbool.h>

struct emulation_data
{
	uint64_t arg0;
	uint64_t arg1;
	uint64_t arg2;
	uint64_t arg3;
	uint64_t arg4;
	uint64_t arg5;
	uint8_t buf[2048];
};

struct call_data
{
	uint64_t retval;
	bool is_emulated;
	bool ready_for_check;
	struct emulation_data em_data;
};




#endif
