#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

char cmd[128];

int main()
{
	sprintf(cmd, "cat /proc/%d/maps", getpid());
	printf("Hello world! pid %d\n", getpid());
//	system(cmd);

	while(1) usleep(5000);

	return 0;
}
