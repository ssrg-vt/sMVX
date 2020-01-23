#define _GNU_SOURCE
#include <stdio.h>

int flag_lmvx = 1;	// TODO: a fake value, need to be deleted.

void associate_all_pkeys();
void store_child_pid();
void set_mvx_active();
void clear_mvx_active();

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

/* This will be preloaded, we should never call this */
void associate_all_pkeys()
{
	fprintf(stderr, "%s: Real associate_all_pkeys called\n", __func__);
}

/* Also preload the child pid */
void store_child_pid(unsigned long pid)
{
	fprintf(stderr, "%s: Real store_child_pid called\n", __func__);
}

/* Preload the setting of mvx */
void set_mvx_active()
{
	fprintf(stderr, "%s: Real set_mvx_active called\n", __func__);
}

/* Preload the clearing of mvx */
void clear_mvx_active()
{
	fprintf(stderr, "%s: Real clear_mvx_active called\n", __func__);
}
