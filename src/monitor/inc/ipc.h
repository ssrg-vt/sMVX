#ifndef __IPC_H__
#define __IPC_H__

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>

struct emulation_data
{
	uint64_t arg0;
	uint64_t arg1;
	uint64_t arg2;
	uint64_t arg3;
	uint64_t arg4;
	uint64_t arg5;
	uint64_t retval;
	uint8_t buf[4096];
};

struct call_data
{
	uint64_t retval;
	bool is_emulated;
	bool ready_for_check;
	bool check_done;
	bool mvx_active;
	struct emulation_data em_data;
};

struct sync_data
{
	/* Mutexes and cond variables */
	pthread_mutex_t monitor_mutex;
	pthread_cond_t master_done;
	pthread_cond_t follower_done;
};




#endif
