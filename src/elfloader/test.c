#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

char cmd[128];

#pragma GCC push_options
#pragma GCC optimize ("O0")
void print_maps(int pid)
{
	sprintf(cmd, "cat /proc/%d/maps", pid);
}
#pragma GCC pop_options

void __attribute__((optimize("O0"))) print_hello(int pid)
{
	printf("Hello world! pid %d\n", pid);
}

int main()
{
	print_maps(getpid());
	print_hello(getpid());

	while(1) usleep(5000);

	return 0;
}
