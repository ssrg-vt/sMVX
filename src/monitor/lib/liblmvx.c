#define _GNU_SOURCE

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sched.h>
//#include <linux/sched.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/wait.h>	// wait()

#include "../inc/lmvx.h"
#include "../inc/log.h"		// log functions
#include "../inc/env.h"
#include "../inc/pkey.h"

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
	log_error("Real associate_all_pkeys called\n");
}

/* Also preload the child pid */
void store_child_pid(unsigned long pid)
{
	log_error("Real store_child_pid called\n");
}

/* Preload the setting of mvx */
void set_mvx_active()
{
	log_error("Real set_mvx_active called\n");
}

/* Preload the clearing of mvx */
void clear_mvx_active()
{
	log_error("Real clear_mvx_active called\n");
}
