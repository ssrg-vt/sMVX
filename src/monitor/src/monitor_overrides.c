/* Libc headers */
#include <dlfcn.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>

/* Local headers */
#include <debug.h>
#include <libmonitor.h>
#include <pkey.h>
#include <loader.h>

/* Defined in monitor_trampoline.c */
extern unsigned long mvx_child_pid;


/* Real functions not being overridden */
int (*real_printf)(const char* restrict fmt, ...);
int (*real_fork)(void);
int (*real_clone)(int (*)(void *), void *, int , void *, ...);
void *(*real_malloc)(size_t);
int (*real_vfprintf)(FILE *restrict, const char *restrict, va_list);
void *(*real_memset)(void *dest, int c, size_t n);
FILE *(*real_fopen)(const char *restrict filename, const char *restrict mode);
FILE *(*real_fdopen)(int fd, const char *mode);

/* Helper function to store the original functions we are overriding*/
void store_original_functions()
{
	if (!(real_printf	= dlsym(RTLD_NEXT, "printf")))
		log_error("printf symbol not found \n");
	if (!(real_fork		= dlsym(RTLD_NEXT, "fork")))
		log_error("fork symbol not found \n");
	if (!(real_clone	= dlsym(RTLD_NEXT, "clone")))
		log_error("clone symbol not found \n");
	if (!(real_malloc	= dlsym(RTLD_NEXT, "malloc")))
		log_error("malloc symbol not found \n");
	if (!(real_vfprintf	= dlsym(RTLD_NEXT, "vfprintf")))
		log_error("vfprintf symbol not found \n");
	if (!(real_memset	= dlsym(RTLD_NEXT, "memset")))
		log_error("memset symbol not found \n");
	if (!(real_fopen	= dlsym(RTLD_NEXT, "fopen")))
		log_error("fopen symbol not found \n");
	if (!(real_fdopen	= dlsym(RTLD_NEXT, "fdopen")))
		log_error("fdopen symbol not found \n");
}

/* Functions we are overriding */
int printf(const char *restrict fmt, ...)
{
	DEACTIVATE();
	va_list args;
	va_start(args, fmt);
	real_printf(fmt, args);
	ACTIVATE();
	return 1;
}

void *memset(void *dest, int c, size_t n)
{
	DEACTIVATE();
	void* retval = real_memset(dest, c, n);
	ACTIVATE();
	return retval;
}

FILE *fopen(const char *restrict filename, const char *restrict mode)
{
	DEACTIVATE();
	FILE* retval = real_fopen(filename, mode);
	ACTIVATE();
	return retval;
}

FILE *fopen64(const char *restrict filename, const char *restrict mode)
{
	DEACTIVATE();
	FILE* retval = real_fopen(filename, mode);
	ACTIVATE();
	return retval;
}

FILE *fdopen(int fd, const char *mode)
{
	DEACTIVATE();
	FILE* retval = real_fdopen(fd, mode);
	ACTIVATE();
	return retval;
}

int vfprintf(FILE *restrict f, const char *restrict fmt, va_list ap)
{
	DEACTIVATE();
	int retval;
	retval = real_vfprintf(f, fmt, ap);
	ACTIVATE();
	return retval;
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

int ld_preload_function(int i)
{
	DEACTIVATE();
	debug_printf("ld_preload_function called, %d\n", i);
	ACTIVATE();
	return 0;
}
