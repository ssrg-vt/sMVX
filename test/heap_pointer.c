#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>

/** lmvx library **/
#include "../inc/lmvx.h"

typedef struct my_struct {
	int a;
	int b;
	int *c;
} my_struct_t;

my_struct_t *ss;

void fun()
{
	printf("[%d] %s\n", getpid(), __func__);
	printf("my_struct_t.a %d, b %d, c %p\n", ++(ss->a), ss->b, ss->c);
}

int main(int argc, char *argv[])
{
	int main_val = 5;

	ss = malloc(sizeof(my_struct_t));
	ss->a = 0;
	ss->b = 20;
	ss->c = &main_val;

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
