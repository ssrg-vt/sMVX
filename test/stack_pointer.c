/**
 * @file stack_pointer.c
 * @author Xiaoguang Wang
 * @brief A unit test case for testing pointers on stack. No need to update
 		pointers on stack.
 * @version 0.1
 * @date 2021-03-30
 * 
 * @copyright Copyright (c) 2021
 * 
 */
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

	/** lmvx library **/
	lmvx_start("fun", 0);
	fun();
	lmvx_end();

	while(1) usleep(5000);

	return 0;
}
