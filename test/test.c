#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>

/** lmvx library **/
#include "../inc/lmvx.h"

#ifdef SYS_gettid
#define gettid()		syscall(SYS_gettid)
#endif

char cmd[128];

void simple_func(int pid)
{
	char* localstring = "Test localstring\n";
	void* to;
	uint64_t rip;
	asm volatile("1: lea 1b(%%rip), %0;": "=a"(rip));

	to = malloc(4096);
	memcpy(to, localstring, 10);

	printf("[%ld %s: rip 0x%lx] ", gettid(), __func__, rip);
	printf("%s --> %s\n", localstring, (char *)to);
//	sprintf(cmd, "cat /proc/%d/maps", pid);
//	printf("%s\n", cmd);
}

int recursive_func(int p_pid, char *name, int cnt)
{
	char *new_name = "parant";

	printf("(pid: %d) Enter %s. Str: %s! Parent pid %d. Local pid %d. Cnt %d.\n",
			getpid(), __func__, name, p_pid, getpid(), cnt);
	name = new_name;
	usleep(1000);
	printf("(pid: %d) Update str. New str: %s\n", getpid(), name);
	usleep(1000);

	if (cnt > 1) recursive_func(p_pid, name, cnt-1);
	printf("(%d) Finish. Cnt %d\n", getpid(), cnt);

	return 0;
}

int main()
{
	/** lmvx library **/
	lmvx_init();

	/** lmvx library **/
	lmvx_start("simple_func", 1, getpid());
	simple_func(getpid());
	/** lmvx library **/
	lmvx_end();

	/** lmvx library **/
	lmvx_start("recursive_func", 3, getpid(), "tom", 3);
	recursive_func(getpid(), "tom", 3);
	/** lmvx library **/
	lmvx_end();

	while(1) usleep(5000);

	return 0;
}
