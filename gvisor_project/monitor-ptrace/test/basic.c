#include <stdio.h>
#include <stdlib.h>	// system
#include <unistd.h>
#include <string.h>

int main()
{
	char name[30];
	char cmd[512];
	sprintf(cmd, "cat /proc/%d/maps", getpid());
	int ret = 0;
	int loop = 1;
	//printf("%s", cmd);
	//system(cmd);

	while (loop) {
		printf("Input your name: \n");
		fflush(stdout);
		ret = scanf("%s", name);
		//ret = read(0, name, 100);
		printf("pid: %d. test. Hi %s. ret %d\n",
		       getpid(), name, ret);
		if (!strncmp(name, "quit", 4)) {
			loop = 0;
		}
	}
	return 0;
}
