#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "lmvx.h"

#ifdef SYS_gettid
#define gettid()		syscall(SYS_gettid)
#endif

char cmd[128];

#pragma GCC push_options
#pragma GCC optimize ("O0")
void print_maps(int pid)
{
	sprintf(cmd, "cat /proc/%d/maps", pid);
	printf("thread id: %ld\n", gettid());
}
#pragma GCC pop_options

int __attribute__((optimize("O0"))) print_hello(int pid, int tid, char *name)
{
	int ret = 0;

	lmvx_start(__func__, pid, tid, name);
	ret = printf("Hello %s! pid %d, tid %d\n", name, pid, tid);
	lmvx_end();

	return ret;
}

int main()
{
	lmvx_init();

	print_maps(getpid());
	print_hello(getpid(), gettid(), "tom");

	while(1) usleep(5000);

	return 0;
}
