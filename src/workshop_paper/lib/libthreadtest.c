#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>

#define NUM_LOOPS (1000000)
/* Library function used to test multi-threaded monguard */
int library_func()
{
	int i = 0;
	int stackvar = 0;
	printf("PID: %lu, stackvar addr: %p, starting loop\n", syscall(SYS_gettid), &stackvar);
	for (i = 0; i < NUM_LOOPS ; ++i, ++stackvar);
	printf("PID: %lu, Final stackvar value: %d\n", syscall(SYS_gettid) ,stackvar);
	return 0;
}
