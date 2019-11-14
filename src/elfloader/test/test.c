#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <unistd.h>

/** lmvx library **/
#include "../inc/lmvx.h"

#ifdef SYS_gettid
#define gettid()		syscall(SYS_gettid)
#endif

char cmd[128];

void simple_func(int pid)
{
	/** lmvx library **/
	if (flag_lmvx) lmvx_start(__func__, 1, pid);

	printf("%s: Local pid: %ld\n", __func__, gettid());

	sprintf(cmd, "cat /proc/%d/maps", pid);
	printf("%s\n", cmd);

	/** lmvx library **/
	if(flag_lmvx) lmvx_end();
}

int recursive_func(int p_pid, char *name, int cnt)
{
	char *new_name = "parant";

	/** lmvx library **/
//	if (flag_lmvx) lmvx_start(__func__, 4, pid, tid, name, cnt);

	printf("(%d) Enter %s. Str: %s! Parent pid %d. Local pid %d. Cnt %d.\n",
			getpid(), __func__, name, p_pid, getpid(), cnt);
	name = new_name;
	usleep(1000);
	printf("(%d) Update str. New str: %s\n", getpid(), name);
	usleep(1000);

	if (cnt > 1) recursive_func(p_pid, name, cnt-1);
	printf("(%d) Finish. Cnt %d\n", getpid(), cnt);

	/** lmvx library **/
//	if(flag_lmvx) lmvx_end();

	return 0;
}

int main()
{
	/** lmvx library **/
	lmvx_init();

	simple_func(getpid());

	/** lmvx library **/
	if (flag_lmvx) lmvx_start("recursive_func", 3, getpid(), "tom", 3);
	recursive_func(getpid(), "tom", 3);
	/** lmvx library **/
	if(flag_lmvx) lmvx_end();

	while(1) usleep(5000);

	return 0;
}
