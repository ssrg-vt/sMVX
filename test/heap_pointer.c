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
int g_val = 2;
int ppid = 0;

/* The func() accesses pointers of a struct allocated on heap. */
void fun()
{
	printf("[%d] %s (%s)\n", getpid(), __func__,
		getpid()==ppid?"parent":"child");
	printf("&ss %p, ss: %p. ss->a %d, b %d, c %p\n", &ss, ss, ++(ss->a),
		ss->b, ss->c);
	sleep(30);
	printf("[%d] 30s sleep done (%s)\n", getpid(),
		getpid()==ppid?"parent":"child");
}

int main(int argc, char *argv[])
{
	int cnt = 2;
	ss = malloc(sizeof(my_struct_t));
	ss->a = 0;
	ss->b = 20;
	ss->c = &g_val;

	/** lmvx library **/
	lmvx_init();
	printf("[%d] %s: before lmvx_start()\n", getpid(), __func__);
	ppid = getpid();

	/** lmvx library **/
	lmvx_start("fun", 0);
	fun();
	lmvx_end();

	printf("[%d] %s: after lmvx_end()\n", getpid(), __func__);
	fun();

	while(cnt--) usleep(1000);

	return 0;
}
