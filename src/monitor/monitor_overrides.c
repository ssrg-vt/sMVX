/* Libc headers */
#include <dlfcn.h>
#include <stdarg.h>
#include <stdlib.h>

/* Local headers */
#include <debug.h>
#include <monitor_trampoline.h>
#include <pkey.h>

/* Defined in monitor_trampoline.c */
extern unsigned long mvx_child_pid;


/* Real functions not being overridden */
int (*real_printf)(const char* restrict fmt, ...);
int (*real_fork)(void);
int (*real_clone)(int (*)(void *), void *, int , void *, ...);
void *(*real_malloc)(size_t);

/* Helper function to store the original functions we are overriding*/
void store_original_functions()
{
	real_printf	= dlsym(RTLD_NEXT, "printf");
	real_fork	= dlsym(RTLD_NEXT, "fork");
	real_clone	= dlsym(RTLD_NEXT, "clone");
	real_malloc	= dlsym(RTLD_NEXT, "malloc");
}

/* Functions we are overriding */
int printf(const char *restrict fmt, ...)
{
	DEACTIVATE();
	real_printf("Intercepted printf!, Actual string: %s\n", fmt);
	ACTIVATE();
	return 1;
}

int fork()
{
	DEACTIVATE();
	int pid = real_fork();
	/* Are we a child process? If yes we need to apply MPK protection scheme
	 * to our addresses */
	if (!pid) {
		//read_proc();
		debug_printf("We are the child process\n");
		return pid;
	}
	debug_printf("Fork not implemented yet, looking into clone first.\n");
	ACTIVATE();
	return pid;
}

int clone(int (*func)(void *), void *stack, int flags, void *arg, ...)
{
	DEACTIVATE();
	int pid;
	va_list args;
	va_start(args, arg);
	pid = real_clone(func, stack, flags, arg, args);
	mvx_child_pid = pid;
	ACTIVATE();
	return pid;
}

/* Passthrough malloc without blocking for now */
void *malloc(size_t n)
{
	DEACTIVATE();
	void* retval;
	retval = real_malloc(n);
	ACTIVATE();
	return retval;
}
