#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>

#ifdef SYS_gettid
#define gettid()		syscall(SYS_gettid)
#endif

char cmd[128];

void simple_func(int pid)
{
	char* localstring = "Test localstring\n";
	void* to;

	char* name = "name";
	int p_pid = 0;
	int cnt = 0x1010;
	int moredata= 0xdeadbeef;

	to = malloc(4096);
	memcpy(to, localstring, 10);

	printf("%s: Local pid: %ld\n", __func__, gettid());
	sprintf(cmd, "cat /proc/%d/maps", pid);
	printf("%s\n", cmd);

	printf("(%d) Enter %s. Str: %s! Parent pid %d. Local pid %d. Cnt %d, Moredata: %d.\n",
			getpid(), __func__, name, p_pid, getpid(), cnt, moredata);
}

int recursive_func(int p_pid, char *name, int cnt)
{
	char *new_name = "parant";

	printf("(%d) Enter %s. Str: %s! Parent pid %d. Local pid %d. Cnt %d.\n",
			getpid(), __func__, name, p_pid, getpid(), cnt);
	name = new_name;
	usleep(1000);
	printf("(%d) Update str. New str: %s\n", getpid(), name);
	usleep(1000);

	if (cnt > 1) recursive_func(p_pid, name, cnt-1);
	printf("(%d) Finish. Cnt %d\n", getpid(), cnt);

	return 0;
}

int main()
{
	/** lmvx library **/
	simple_func(getpid());
	/** lmvx library **/

	/** lmvx library **/
	recursive_func(getpid(), "tom", 3);
	/** lmvx library **/

	while(1) usleep(5000);

	return 0;
}
