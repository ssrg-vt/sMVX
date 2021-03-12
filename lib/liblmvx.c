#define _GNU_SOURCE
#include <stdio.h>

/* Placeholder function: init lMVX environment. */
int lmvx_init(void)
{
	fprintf(stderr, "%s: vannila mode\n", __func__);
	return 0;
}

/* Placeholder function: lMVX spawns a variant thread. */
void lmvx_start(const char *func_name, int argc, ...)
{
	fprintf(stderr, "%s: vannila mode\n", __func__);
}

/* Placeholder function: lMVX finishes the variant thread. */
void lmvx_end(void)
{
	fprintf(stderr, "%s: vannila mode\n", __func__);
}
