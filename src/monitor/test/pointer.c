#include <stdio.h>
#include <unistd.h>
#include <inttypes.h>

/** lmvx library **/
#include "../inc/lmvx.h"

int *p_global;
int g_a = 10;
void (*g_p_fn)(int *);

void fun(int *p_para)
{
	uint64_t rip;
	asm volatile("1: lea 1b(%%rip), %0;": "=a"(rip));

	printf("%s: *p_para %d. rip %" PRIx64 ". &p_global %p, &g_a %p, g_p_fn %p %p\n",
			__func__, *p_para, rip, &p_global, &g_a, g_p_fn, &g_p_fn);
}

int main(int argc, char *argv[])
{
	void (*p_fn)(int *) = &fun;

	g_p_fn = &fun;
	/** lmvx library **/
	lmvx_init();

	printf("%s: pid %d. &p_fn %p\n", __func__, getpid(), &p_fn);

	/** lmvx library **/
	lmvx_start("g_p_fn", 1, &g_a);
	g_p_fn(&g_a);
	lmvx_end();

	p_global = &g_a;
	/** lmvx library **/
	lmvx_start("fun", 1, p_global);
	fun(p_global);
	lmvx_end();

	p_fn(&g_a);

	while(1) usleep(5000);

	return 0;
}
