#include <stdio.h>
#include <unistd.h>
#include <inttypes.h>

/** lmvx library **/
#include "../inc/lmvx.h"

void fun()
{
	uint64_t rip;
	uint64_t *p_local = &rip;
	asm volatile("1: lea 1b(%%rip), %0;": "=a"(rip));

	printf("[%d] %s: p_local %p, *p_local 0x%lx\n",
			getpid(), __func__, p_local, *p_local);
}

int main(int argc, char *argv[])
{
	/** lmvx library **/
	lmvx_init();

	fun();

	printf("[%d] %s\n", getpid(), __func__);
	//printf("%s: pid %d.\n", __func__, getpid());
	/** lmvx library **/
	lmvx_start("fun", 0);
	fun();
	lmvx_end();

	while(1) usleep(5000);

	return 0;
}
