#include <stdio.h>
#include <unistd.h>
#include <inttypes.h>

/** lmvx library **/
#include "../inc/lmvx.h"

typedef struct my_struct {
	int a;
	int b;
	int *c;
} my_struct_t;

my_struct_t ss;		/* A global struct */

void fun()
{
	printf("[%d] %s\n", getpid(), __func__);
	printf("my_struct_t.a %d, b %d, c %p\n", ++(ss.a), ss.b, ss.c);
}

int main(int argc, char *argv[])
{
	int main_val = 5;
	ss.a = 0;
	ss.b = 20;
	ss.c = &main_val;	/* A member of the struct points to a stack variable */

	/** lmvx library **/
	lmvx_init();

	fun();

	printf("[%d] %s\n", getpid(), __func__);
	/** lmvx library **/
	lmvx_start("fun", 0);
	fun();
	lmvx_end();

	fun();

	while(1) usleep(5000);

	return 0;
}
