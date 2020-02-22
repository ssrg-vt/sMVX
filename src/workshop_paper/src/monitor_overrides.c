/* Libc headers */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <setjmp.h>
#include <errno.h>

/* Local headers */
#include <debug.h>
#include <libmonitor.h>
#include <pkey.h>
#include <loader.h>


/* Shared memory */
struct call_data* calldata_ptr;
struct sync_data* syncdata_ptr;

/* Real functions not being overridden */
int (*real_printf)(const char* restrict fmt, ...);
int (*real_fork)(void);
int (*real_clone)(int (*)(void *), void *, int , void *, ...);
void *(*real_malloc)(size_t);
int (*real_vfprintf)(FILE *restrict, const char *restrict, va_list);
int (*real_fprintf)(FILE *restrict f, const char *restrict fmt, ...);
void *(*real_memset)(void *dest, int c, size_t n);
FILE *(*real_fopen)(const char *restrict filename, const char *restrict mode);
FILE *(*real_fdopen)(int fd, const char *mode);
int (*real_fscanf)(FILE *restrict f, const char *restrict fmt, ...);
int (*real_fclose)(FILE *f);
int (*real_remove)(const char *path);
int (*real_fputc)(int c, FILE *f);
int (*real_fflush)(FILE *f);
int (* real_vsprintf)(char *restrict s, const char *restrict fmt, va_list ap);
int (*real_puts)(const char *s);
int (*real_vprintf)(const char *restrict fmt, va_list ap);
void *(*real_memcpy)(void *restrict dest, const void *restrict src, size_t n);
void *(*real_free)(void *p);
ssize_t (*real_recv)(int fd, void *buf, size_t len, int flags);
int (*real_memcmp)(const void *vl, const void *vr, size_t n);
ssize_t (*real_sendfile)(int out_fd, int in_fd, off_t *ofs, size_t count);
ssize_t (*real_writev)(int fd, const struct iovec *iov, int count);
ssize_t (*real_write)(int fd, const void *buf, size_t count);
int (*real_open)(const char *filename, int flags, ...);
int (*real_close)(int fd);
int (*real_epoll_pwait)(int fd, struct epoll_event *ev, int cnt, int to, const sigset_t
		*sigs);
int (*real_epoll_wait)(int fd, struct epoll_event *ev, int cnt, int to);
int (*real_accept4)(int fd, struct sockaddr *restrict addr, socklen_t *restrict len,
	       int flg);
int (*real_epoll_ctl)(int fd, int op, int fd2, struct epoll_event *ev);
int (*real_fstat)(int fd, struct stat *st);
ssize_t (*real_recv)(int fd, void *buf, size_t len, int flags);
int (*real_shutdown)(int fd, int how);
int (*real_setsockopt)(int fd, int level, int optname, const void *optval,
		       socklen_t optlen);
int (*real_gettimeofday)(struct timeval *restrict tv, void *restrict tz);
struct tm *(*real_localtime_r)(const time_t *restrict t, struct tm *restrict
				 tm);
int (*real_atoi)(const char *s);
double (*real_atof)(const char *s);
int (*real_putc)(int c, FILE *f);
unsigned long (*real_strtoul)(const char *restrict s, char **restrict p, int base);
void *(*real_calloc)(size_t m, size_t n);
int (*real_fputs)(const char *restrict s, FILE *restrict f);
size_t (*real_strlen)(const char *s);
int (*real_strcmp)(const char *l, const char *r);
char *(*real_strchr)(const char *s, int c);
size_t (*real_fwrite)(const void *restrict src, size_t size, size_t nmemb, FILE
		      *restrict f);
void *(*real_realloc)(void *p, size_t n);
int (*real_strncmp)(const char *_l, const char *_r, size_t n);
int (*real_setjmp) (jmp_buf env);
char *(*real_strcpy)(char *restrict dest, const char *restrict src);
char *(*real_getenv)(const char *name);
int *(*real_errno_location)(void);
int (*real_stat)(const char *restrict path, struct stat *restrict buf);
int (*real_getpagesize)(void);
int (*real_ferror)(FILE *f);
int (*real_vsscanf)(const char *restrict s, const char *restrict fmt, va_list
		    ap);
char *(*real_fgets)(char *restrict s, int n, FILE *restrict f);
int (*real_putchar)(int c);
int (*real_getc)(FILE *f);
double (*real_pow)(double x, double y);
int (*real_toupper)(int c);
int (*real_tolower)(int c);
double (*real_floor)(double x);
double (*real_ceil)(double x);
void (*real_setbuf)(FILE *restrict f, char *restrict buf);
int (*real_setvbuf)(FILE *restrict f, char *restrict buf, int type, size_t
		    size);
int (*real_feof)(FILE *f);
double (*real_exp)(double x);
char *(*real_strtok)(char *restrict s, const char *restrict sep);
char *(*real_strncpy)(char *restrict d, const char *restrict s, size_t n);
double (*real_log)(double x);
float (*real_floorf)(float x);
void (*real_rewind)(FILE *f);
long (*real_ftell)(FILE *f);
void *(*real_memmove)(void *dest, const void *src, size_t n);
size_t (*real_strcspn)(const char *s, const char *c);
size_t (*real_fread)(void *restrict destv, size_t size, size_t nmemb, FILE
		     *restrict f);
char *(*real_strcat)(char *restrict dest, const char *restrict src);
double (*real_difftime)(time_t t1, time_t t0);
char *(*real_stpcpy)(char *restrict d, const char *restrict s);
void (*real_exit)(int code);

/* Helper function to store the original functions we are overriding*/
void store_original_functions()
{
	if (!(real_printf	= dlsym(RTLD_NEXT, "printf")))
		log_error("printf symbol not found ");
	if (!(real_vprintf	= dlsym(RTLD_NEXT, "vprintf")))
		log_error("vprintf symbol not found ");
	if (!(real_fork		= dlsym(RTLD_NEXT, "fork")))
		log_error("fork symbol not found ");
	if (!(real_clone	= dlsym(RTLD_NEXT, "clone")))
		log_error("clone symbol not found ");
	if (!(real_malloc	= dlsym(RTLD_NEXT, "malloc")))
		log_error("malloc symbol not found ");
	if (!(real_vfprintf	= dlsym(RTLD_NEXT, "vfprintf")))
		log_error("vfprintf symbol not found ");
	if (!(real_fprintf	= dlsym(RTLD_NEXT, "fprintf")))
		log_error("fprintf symbol not found ");
	if (!(real_memset	= dlsym(RTLD_NEXT, "memset")))
		log_error("memset symbol not found ");
	if (!(real_fopen	= dlsym(RTLD_NEXT, "fopen")))
		log_error("fopen symbol not found ");
	if (!(real_fdopen	= dlsym(RTLD_NEXT, "fdopen")))
		log_error("fdopen symbol not found ");
	if (!(real_fscanf	= dlsym(RTLD_NEXT, "fscanf")))
		log_error("fscanf symbol not found ");
	if (!(real_fclose	= dlsym(RTLD_NEXT, "fclose")))
		log_error("fclose symbol not found ");
	if (!(real_remove	= dlsym(RTLD_NEXT, "remove")))
		log_error("remove symbol not found ");
	if (!(real_fputc	= dlsym(RTLD_NEXT, "fputc")))
		log_error("fputc symbol not found ");
	if (!(real_fflush	= dlsym(RTLD_NEXT, "fflush")))
		log_error("fflush symbol not found ");
	if (!(real_vsprintf	= dlsym(RTLD_NEXT, "vsprintf")))
		log_error("vsprintf symbol not found ");
	if (!(real_puts		= dlsym(RTLD_NEXT, "puts")))
		log_error("puts symbol not found ");
	if (!(real_memcpy	= dlsym(RTLD_NEXT, "memcpy")))
		log_error("memcpy symbol not found ");
	if (!(real_free		= dlsym(RTLD_NEXT, "free")))
		log_error("free symbol not found ");
	if (!(real_recv		= dlsym(RTLD_NEXT, "recv")))
		log_error("recv symbol not found ");
	if (!(real_memcmp	= dlsym(RTLD_NEXT, "memcmp")))
		log_error("memcmp symbol not found ");
	if (!(real_sendfile	= dlsym(RTLD_NEXT, "sendfile")))
		log_error("sendfile symbol not found ");
	if (!(real_writev	= dlsym(RTLD_NEXT, "writev")))
		log_error("writev symbol not found ");
	if (!(real_write	= dlsym(RTLD_NEXT, "write")))
		log_error("write symbol not found ");
	if (!(real_open		= dlsym(RTLD_NEXT, "open")))
		log_error("open symbol not found ");
	if (!(real_close	= dlsym(RTLD_NEXT, "close")))
		log_error("close symbol not found ");
	if (!(real_epoll_pwait	= dlsym(RTLD_NEXT, "epoll_pwait")))
		log_error("epoll_pwait symbol not found ");
	if (!(real_epoll_wait	= dlsym(RTLD_NEXT, "epoll_wait")))
		log_error("epoll_wait symbol not found ");
	if (!(real_accept4	= dlsym(RTLD_NEXT, "accept4")))
		log_error("accept4 symbol not found ");
	if (!(real_epoll_ctl	= dlsym(RTLD_NEXT, "epoll_ctl")))
		log_error("epoll_ctl symbol not found ");
	if (!(real_fstat	= dlsym(RTLD_NEXT, "fstat")))
		log_error("fstat symbol not found ");
	if (!(real_recv		= dlsym(RTLD_NEXT, "recv")))
		log_error("recv symbol not found ");
	if (!(real_shutdown	= dlsym(RTLD_NEXT, "shutdown")))
		log_error("shutdown symbol not found ");
	if (!(real_setsockopt	= dlsym(RTLD_NEXT, "setsockopt")))
		log_error("setsockopt symbol not found ");
	if (!(real_gettimeofday	= dlsym(RTLD_NEXT, "gettimeofday")))
		log_error("gettimeofday symbol not found ");
	if (!(real_localtime_r= dlsym(RTLD_NEXT, "localtime_r")))
		log_error("__localtime_r symbol not found ");
	if (!(real_atoi= dlsym(RTLD_NEXT, "atoi")))
		log_error("atoi symbol not found ");
	if (!(real_atof= dlsym(RTLD_NEXT, "atof")))
		log_error("atof symbol not found ");
	if (!(real_putc= dlsym(RTLD_NEXT, "putc")))
		log_error("putc symbol not found ");
	if (!(real_strtoul= dlsym(RTLD_NEXT, "strtoul")))
		log_error("strtoul symbol not found ");
	if (!(real_calloc= dlsym(RTLD_NEXT, "calloc")))
		log_error("calloc symbol not found ");
	if (!(real_fputs= dlsym(RTLD_NEXT, "fputs")))
		log_error("fputs symbol not found ");
	if (!(real_strlen= dlsym(RTLD_NEXT, "strlen")))
		log_error("strlen symbol not found ");
	if (!(real_strcmp= dlsym(RTLD_NEXT, "strcmp")))
		log_error("strcmp symbol not found ");
	if (!(real_strchr= dlsym(RTLD_NEXT, "strchr")))
		log_error("strchr symbol not found ");
	if (!(real_fwrite= dlsym(RTLD_NEXT, "fwrite")))
		log_error("fwrite symbol not found ");
	if (!(real_realloc= dlsym(RTLD_NEXT, "realloc")))
		log_error("realloc symbol not found ");
	if (!(real_strncmp= dlsym(RTLD_NEXT, "strncmp")))
		log_error("strncmp symbol not found ");
	if (!(real_setjmp= dlsym(RTLD_NEXT, "setjmp")))
		log_error("setjmp symbol not found ");
	if (!(real_strcpy= dlsym(RTLD_NEXT, "strcpy")))
		log_error("strcpy symbol not found ");
	if (!(real_getenv= dlsym(RTLD_NEXT, "getenv")))
		log_error("getenv symbol not found ");
	if (!(real_errno_location= dlsym(RTLD_NEXT, "__errno_location")))
		log_error("errno_location symbol not found ");
	if (!(real_stat= dlsym(RTLD_NEXT, "stat")))
		log_error("stat symbol not found ");
	if (!(real_getpagesize= dlsym(RTLD_NEXT, "getpagesize")))
		log_error("getpagesize symbol not found ");
	if (!(real_ferror= dlsym(RTLD_NEXT, "ferror")))
		log_error("ferror symbol not found ");
	if (!(real_vsscanf= dlsym(RTLD_NEXT, "vsscanf")))
		log_error("vsscanf symbol not found ");
	if (!(real_fgets= dlsym(RTLD_NEXT, "fgets")))
		log_error("fgets symbol not found ");
	if (!(real_putchar= dlsym(RTLD_NEXT, "putchar")))
		log_error("putchar symbol not found ");
	if (!(real_getc= dlsym(RTLD_NEXT, "getc")))
		log_error("getc symbol not found ");
	if (!(real_pow= dlsym(RTLD_NEXT, "pow")))
		log_error("pow symbol not found ");
	if (!(real_toupper= dlsym(RTLD_NEXT, "toupper")))
		log_error("toupper symbol not found ");
	if (!(real_floor= dlsym(RTLD_NEXT, "floor")))
		log_error("floor symbol not found ");
	if (!(real_ceil= dlsym(RTLD_NEXT, "ceil")))
		log_error("ceil symbol not found ");
	if (!(real_tolower= dlsym(RTLD_NEXT, "tolower")))
		log_error("tolower symbol not found ");
	if (!(real_setbuf= dlsym(RTLD_NEXT, "setbuf")))
		log_error("setbuf symbol not found ");
	if (!(real_setvbuf= dlsym(RTLD_NEXT, "setvbuf")))
		log_error("setvbuf symbol not found ");
	if (!(real_feof= dlsym(RTLD_NEXT, "feof")))
		log_error("feof symbol not found ");
	if (!(real_exp= dlsym(RTLD_NEXT, "exp")))
		log_error("exp symbol not found ");
	if (!(real_strtok= dlsym(RTLD_NEXT, "strtok")))
		log_error("strtok symbol not found ");
	if (!(real_strncpy= dlsym(RTLD_NEXT, "strncpy")))
		log_error("strncpy symbol not found ");
	if (!(real_log= dlsym(RTLD_NEXT, "log")))
		log_error("log symbol not found ");
	if (!(real_floorf= dlsym(RTLD_NEXT, "floorf")))
		log_error("floorf symbol not found ");
	if (!(real_rewind= dlsym(RTLD_NEXT, "rewind")))
		log_error("rewind symbol not found ");
	if (!(real_ftell= dlsym(RTLD_NEXT, "ftell")))
		log_error("ftell symbol not found ");
	if (!(real_memmove= dlsym(RTLD_NEXT, "memmove")))
		log_error("memmove symbol not found ");
	if (!(real_strcspn= dlsym(RTLD_NEXT, "strcspn")))
		log_error("strcspn symbol not found ");
	if (!(real_fread= dlsym(RTLD_NEXT, "fread")))
		log_error("fread symbol not found ");
	if (!(real_strcat= dlsym(RTLD_NEXT, "strcat")))
		log_error("strcat symbol not found ");
	if (!(real_difftime= dlsym(RTLD_NEXT, "difftime")))
		log_error("difftime symbol not found ");
	if (!(real_stpcpy= dlsym(RTLD_NEXT, "stpcpy")))
		log_error("stpcpy symbol not found ");
	if (!(real_exit= dlsym(RTLD_NEXT, "exit")))
		log_error("exit symbol not found ");
}

/* Functions we are overriding */
int printf(const char *restrict fmt, ...)
{
	DEACTIVATE();
	int retval;
	va_list args;
	va_start(args, fmt);
	log_debug("Called %s PID:%u", __func__, getpid());
	retval = real_vprintf(fmt, args);
	va_end(args);
	ACTIVATE();
	return retval;
}

//int scanf(const char *restrict fmt, ...)
//{
//	DEACTIVATE();
//	va_list args;
//
//	ACTIVATE();
//	return 1;
//}
//
void *memset(void *dest, int c, size_t n)
{
	DEACTIVATE();
	void* retval = real_memset(dest, c, n);
	log_debug("Called %s PID:%u", __func__, getpid());
	ACTIVATE();
	return retval;
}

void *memcpy(void *restrict dest, const void *restrict src, size_t n)
{
	DEACTIVATE();
	void* retval = real_memcpy(dest, src, n);
	log_debug("Called %s PID:%u", __func__, getpid());
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

//FILE *fopen64(const char *restrict filename, const char *restrict mode)
//{
//	DEACTIVATE();
//	FILE* retval = real_fopen(filename, mode);
//	ACTIVATE();
//	return retval;
//}

//FILE *fdopen(int fd, const char *mode)
//{
//	DEACTIVATE();
//	FILE* retval = real_fdopen(fd, mode);
//	ACTIVATE();
//	return retval;
//}
//
int vfprintf(FILE *restrict f, const char *restrict fmt, va_list ap)
{
	DEACTIVATE();
	int retval;
	retval = real_vfprintf(f, fmt, ap);
	ACTIVATE();
	return retval;
}

int fprintf(FILE *restrict f, const char *restrict fmt, ...)
{
	DEACTIVATE();
	int retval;
	va_list args;
	va_start(args, fmt);
	/* Do not call real_fprintf, call vfprintff as this override is already
	 * variadic */
	retval = real_vfprintf(f, fmt, args);
	va_end(args);
	ACTIVATE();
	return retval;
}

int sprintf(char *restrict s, const char *restrict fmt, ...)
{
	DEACTIVATE();
	int retval;
	va_list args;
	va_start(args, fmt);
	retval = real_vsprintf(s, fmt, args);
	va_end(args);
	ACTIVATE();
	return retval;
}

int puts(const char *s)
{
	DEACTIVATE();
	int retval;
	retval = real_puts(s);
	log_debug("Called %s PID:%u", __func__, getpid());
	ACTIVATE();
	return retval;
}
//
//int fscanf(FILE *restrict f, const char *restrict fmt, ...)
//{
//	DEACTIVATE();
//	int retval;
//	va_list args;
//	va_start(args, fmt);
//	/* Do not call real_fscanf, call vfscanf  as this override is already
//	 * variadic */
//	retval = vfscanf(f, fmt, args);
//	va_end(args);
//	ACTIVATE();
//	return retval;
//}

int fclose(FILE *f)
{
	DEACTIVATE();
	int retval;
	retval = real_fclose(f);
	ACTIVATE();
	return retval;
}

//int remove(const char *path)
//{
//	DEACTIVATE();
//	int retval;
//	retval = real_remove(path);
//	ACTIVATE();
//	return retval;
//}
//
//int fork()
//{
//	DEACTIVATE();
//	int pid = real_fork();
//	/* Are we a child process? If yes we need to apply MPK protection scheme
//	 * to our addresses */
//	if (!pid) {
//		//read_proc();
//		debug_printf("We are the child process");
//		return pid;
//	}
//	debug_printf("Fork not implemented yet, looking into clone first.");
//	ACTIVATE();
//	return pid;
//}

//int clone(int (*func)(void *), void *stack, int flags, void *arg, ...)
//{
//	DEACTIVATE();
//	va_list args;
//	int retval;
//	if(calldata_ptr->mvx_active){
//		pthread_mutex_lock(&(syncdata_ptr->monitor_mutex));
//		/* Have child check */
//		if (is_child()){
//		}
//		else{
//			va_start(args, arg);
//			retval = real_clone(func, stack, flags, arg, args);
//		}
//		pthread_mutex_unlock(&(syncdata_ptr->monitor_mutex));
//	}
//	else{
//		va_start(args, arg);
//		retval = real_clone(func, stack, flags, arg, args);
//	}
//	ACTIVATE();
//	return retval;
//}

/* Passthrough malloc without blocking for now */
void *malloc(size_t n)
{
	DEACTIVATE();
	void* retval;
	retval = real_malloc(n);
	log_debug("Called %s PID:%u", __func__, getpid());
	ACTIVATE();
	return retval;
}

void free(void* p)
{
	DEACTIVATE();
	log_debug("Called %s PID:%u", __func__, getpid());
	real_free(p);
	ACTIVATE();
}
//
//int ld_preload_function(int i)
//{
//	DEACTIVATE();
//	debug_printf("ld_preload_function called, %d", i);
//	ACTIVATE();
//	return 0;
//}

int fputc(int c, FILE *f)
{
	DEACTIVATE();
	int retval;
	retval = real_fputc(c, f);
	ACTIVATE();
	return retval;
}

int fflush(FILE *f)
{
	DEACTIVATE();
	int retval;
	retval = real_fflush(f);
	ACTIVATE();
	return retval;
}

//ssize_t recv(int fd, void *buf, size_t len, int flags)
//{
//	DEACTIVATE();
//	ssize_t retval;
//	retval = real_recv(fd, buf, len, flags);
//	ACTIVATE();
//	return retval;
//}

int memcmp(const void *vl, const void *vr, size_t n)
{
	DEACTIVATE();
	int retval;
	retval = real_memcmp(vl, vr, n);
	ACTIVATE();
	return retval;
}

ssize_t sendfile(int out_fd, int in_fd, off_t *ofs, size_t count)
{
	DEACTIVATE();
	ssize_t retval;
	log_debug("Called %s PID:%u", __func__, getpid());
	retval = real_sendfile(out_fd, in_fd, ofs, count);
	ACTIVATE();
	return retval;
}

ssize_t writev(int fd, const struct iovec *iov, int count)
{
	DEACTIVATE();
	ssize_t retval;
	log_debug("Called %s PID:%u", __func__, getpid());
	retval = real_writev(fd, iov, count);
	ACTIVATE();
	return retval;
}

ssize_t write(int fd, const void *buf, size_t count)
{
	DEACTIVATE();
	ssize_t retval;
	log_debug("Called %s PID:%u", __func__, getpid());
	retval = real_write(fd, buf, count);
	ACTIVATE();
	return retval;
}

int open(const char *filename, int flags, ...)
{
	DEACTIVATE();
	unsigned mode = 0;
	int retval;
	log_debug("Called %s PID:%u", __func__, getpid());
	retval = real_open(filename, flags);
	ACTIVATE();
	return retval;
}

int close(int fd)
{
	DEACTIVATE();
	int retval;
	log_debug("Called %s PID:%u", __func__, getpid());
	retval = real_close(fd);
	ACTIVATE();
	return retval;
}

int epoll_pwait(int fd, struct epoll_event *ev, int cnt, int to, const sigset_t *sigs)
{
	DEACTIVATE();
	int retval;
	log_debug("Called %s PID:%u", __func__, getpid());
	retval = real_epoll_pwait(fd, ev, cnt, to, sigs);
	ACTIVATE();
	return retval;
}

int epoll_wait(int fd, struct epoll_event *ev, int cnt, int to)
{
	DEACTIVATE();
	int retval;
	log_debug("Called %s PID:%u", __func__, getpid());
	retval = real_epoll_wait(fd, ev, cnt, to);
	ACTIVATE();
	return retval;
}

int accept4(int fd, struct sockaddr *restrict addr, socklen_t *restrict len, int flg)
{
	DEACTIVATE();
	int retval;
	log_debug("Called %s PID:%u", __func__, getpid());
	retval = real_accept4(fd, addr, len, flg);
	ACTIVATE();
	return retval;
}

int epoll_ctl(int fd, int op, int fd2, struct epoll_event *ev)
{
	DEACTIVATE();
	int retval;
	log_debug("Called %s PID:%u", __func__, getpid());
	retval = real_epoll_ctl(fd, op ,fd2, ev);
	ACTIVATE();
	return retval;
}

int fstat(int fd, struct stat *st)
{
	DEACTIVATE();
	int retval;
	log_debug("Called %s PID:%u", __func__, getpid());
	retval = real_fstat(fd, st);
	ACTIVATE();
	return retval;
}

ssize_t recv(int fd, void *buf, size_t len, int flags)
{
	DEACTIVATE();
	int retval;
	log_debug("Called %s PID:%u", __func__, getpid());
	retval = real_recv(fd, buf, len, flags);
	ACTIVATE();
	return retval;
}

int shutdown(int fd, int how)
{
	DEACTIVATE();
	int retval;
	log_debug("Called %s PID:%u", __func__, getpid());
	retval = real_shutdown(fd, how);
	ACTIVATE();
	return retval;
}

int setsockopt(int fd, int level, int optname, const void *optval, socklen_t optlen)
{
	DEACTIVATE();
	int retval;
	log_debug("Called %s PID:%u", __func__, getpid());
	retval = real_setsockopt(fd, level, optname, optval,
						 optlen);
	ACTIVATE();
	return retval;
}

#if 0
int gettimeofday(struct timeval *restrict tv, void *restrict tz)
{
	DEACTIVATE();
	int retval;
	if(calldata_ptr->mvx_active){
		pthread_mutex_lock(&(syncdata_ptr->monitor_mutex));
		/* Have child check */
		if (is_child()){
			log_debug("Child called %s", __func__);
			while(!calldata_ptr->ready_for_check)
				pthread_cond_wait(&(syncdata_ptr->master_done), &(syncdata_ptr->monitor_mutex));

			/* Perform function name check to ensure sequence */
			check_function_names(__func__);
			/* Perform retval emulation */
			retval = calldata_ptr->em_data.retval;
			/* Perform buf emulation */
			real_memcpy(tv, calldata_ptr->em_data.buf, sizeof(struct
									  timeval));
			real_memset(calldata_ptr->em_data.buf, 0, sizeof(struct
									 timeval));
			log_debug("Child is done with %s, retval: %u", __func__, retval);
			calldata_ptr->ready_for_check = false;
			pthread_cond_signal(&(syncdata_ptr->follower_done));
		}
		else{
			log_debug("Master called %s", __func__);
			while(calldata_ptr->ready_for_check )
				pthread_cond_wait(&(syncdata_ptr->follower_done),
						  &(syncdata_ptr->monitor_mutex));
			store_function_name(__func__);
			retval = real_gettimeofday(tv, tz);
			/* Copy retval to shared memory */
			calldata_ptr->em_data.retval = (uint64_t)retval;
			/* Copy buffer data to shared memory */
			real_memcpy(calldata_ptr->em_data.buf, tv, sizeof(struct
									  timeval));

			calldata_ptr->ready_for_check = true;
			pthread_cond_signal(&(syncdata_ptr->master_done));
			log_debug("Master is done with %s, signalling child, retval: %u", __func__, retval);
		}
		pthread_mutex_unlock(&(syncdata_ptr->monitor_mutex));
	}
	else{
		log_debug("Master called %s, mvx isn't active, PID:%u", __func__, getpid());
		retval = real_gettimeofday(tv, tz);
	}
	ACTIVATE();
	return retval;
}
#endif

struct tm *localtime_r(const time_t *restrict t, struct tm *restrict tm)
{
	DEACTIVATE();
	struct tm* retval;
	log_debug("Called %s PID:%u", __func__, getpid());
	retval = real_localtime_r(t, tm);
	ACTIVATE();
	return retval;
}

int atoi(const char *s)
{
	DEACTIVATE();
	int retval;
	log_debug("Called %s PID:%u", __func__, getpid());
	retval = real_atoi(s);
	ACTIVATE();
	return retval;
}

double atof(const char *s)
{
	DEACTIVATE();
	double retval;
	log_debug("Called %s PID:%u", __func__, getpid());
	retval = real_atof(s);
	ACTIVATE();
	return retval;
}

int putc(int c, FILE *f)
{
	DEACTIVATE();
	int retval;
	log_debug("Called %s PID:%u", __func__, getpid());
	retval = real_putc(c, f);
	ACTIVATE();
	return retval;
}

unsigned long strtoul(const char *restrict s, char **restrict p, int base)
{
	DEACTIVATE();
	unsigned long retval;
	log_debug("Called %s PID:%u", __func__, getpid());
	retval = real_strtoul(s, p, base);
	ACTIVATE();
	return retval;
}

void *calloc(size_t m, size_t n)
{
	DEACTIVATE();
	void* retval;
	log_debug("Called %s PID:%u", __func__, getpid());
	retval = real_calloc(m,n);
	ACTIVATE();
	return retval;
}

int fputs(const char *restrict s, FILE *restrict f)
{
	DEACTIVATE();
	int retval;
	log_debug("Called %s PID:%u", __func__, getpid());
	retval = real_fputs(s,f);
	ACTIVATE();
	return retval;
}

size_t strlen(const char *s)
{
	DEACTIVATE();
	size_t retval;
	log_debug("Called %s PID:%u", __func__, getpid());
	retval = real_strlen(s);
	ACTIVATE();
	return retval;
}

int strcmp(const char *l, const char *r)
{
	DEACTIVATE();
	int retval;
	log_debug("Called %s PID:%u", __func__, getpid());
	retval = real_strcmp(l, r);
	ACTIVATE();
	return retval;
}

char *strchr(const char *s, int c)
{
	DEACTIVATE();
	char* retval;
	log_debug("Called %s PID:%u", __func__, getpid());
	retval = real_strchr(s, c);
	ACTIVATE();
	return retval;
}

size_t fwrite(const void *restrict src, size_t size, size_t nmemb, FILE *restrict f)
{
	DEACTIVATE();
	size_t retval;
	log_debug("Called %s PID:%u", __func__, getpid());
	retval = real_fwrite(src, size, nmemb, f);
	ACTIVATE();
	return retval;
}

void *realloc(void *p, size_t n)
{
	DEACTIVATE();
	void* retval;
	log_debug("Called %s PID:%u", __func__, getpid());
	retval = real_realloc(p, n);
	ACTIVATE();
	return retval;
}

int strncmp(const char *_l, const char *_r, size_t n)
{
	DEACTIVATE();
	int retval;
	log_debug("Called %s PID:%u", __func__, getpid());
	retval = real_strncmp(_l, _r, n);
	ACTIVATE();
	return retval;
}

int setjmp(jmp_buf env)
{
	DEACTIVATE();
	int retval;
	log_debug("Called %s PID:%u", __func__, getpid());
	retval = real_setjmp(env);
	ACTIVATE();
	return retval;
}

//void (*signal(int signo, void (*func )(int)))(int)
//{
//	DEACTIVATE();
//	void (*retval)(int);
//	retval = real_signal(signo, func);
//	ACTIVATE();
//	return retval;
//}

char *strcpy(char *restrict dest, const char *restrict src)
{
	DEACTIVATE();
	char* retval;
	log_debug("Called %s PID:%u", __func__, getpid());
	retval = real_strcpy(dest, src);
	ACTIVATE();
	return retval;
}

char *getenv(const char *name)
{
	DEACTIVATE();
	char* retval;
	log_debug("Called %s PID:%u", __func__, getpid());
	retval = real_getenv(name);
	ACTIVATE();
	return retval;
}

int *__errno_location(void)
{
	DEACTIVATE();
	int* retval;
	log_debug("Called %s PID:%u", __func__, getpid());
	retval = real_errno_location();
	ACTIVATE();
	return retval;
}

int stat(const char *restrict path, struct stat *restrict buf)
{
	DEACTIVATE();
	int retval;
	log_debug("Called %s PID:%u", __func__, getpid());
	retval = real_stat(path, buf);
	ACTIVATE();
	return retval;
}

int getpagesize(void)
{
	DEACTIVATE();
	int retval;
	log_debug("Called %s PID:%u", __func__, getpid());
	retval = real_getpagesize();
	ACTIVATE();
	return retval;
}

int ferror(FILE *f)
{
	DEACTIVATE();
	int retval;
	log_debug("Called %s PID:%u", __func__, getpid());
	retval = real_ferror(f);
	ACTIVATE();
	return retval;
}

int sscanf(const char *restrict s, const char *restrict fmt, ...)
{
	DEACTIVATE();
	int retval;
	va_list args;
	va_start(args, fmt);
	/* Do not call real_fprintf, call vfprintff as this override is already
	 * variadic */
	retval = real_vsscanf(s, fmt, args);
	va_end(args);
	ACTIVATE();
	return retval;
}

char *fgets(char *restrict s, int n, FILE *restrict f)
{
	DEACTIVATE();
	char* retval;
	log_debug("Called %s PID:%u", __func__, getpid());
	retval = real_fgets(s,n, f);
	ACTIVATE();
	return retval;
}

int putchar(int c)
{
	DEACTIVATE();
	int retval;
	log_debug("Called %s PID:%u", __func__, getpid());
	retval = real_putchar(c);
	ACTIVATE();
	return retval;
}

int getc(FILE *f)
{
	DEACTIVATE();
	int retval;
	log_debug("Called %s PID:%u", __func__, getpid());
	retval = real_getc(f);
	ACTIVATE();
	return retval;
}

double pow(double x, double y)
{
	DEACTIVATE();
	double retval;
	log_debug("Called %s PID:%u", __func__, getpid());
	retval = real_pow(x, y);
	ACTIVATE();
	return retval;
}

int toupper(int c)
{
	DEACTIVATE();
	int retval;
	log_debug("Called %s PID:%u", __func__, getpid());
	retval = real_toupper(c);
	ACTIVATE();
	return retval;
}

int tolower(int c)
{
	DEACTIVATE();
	int retval;
	log_debug("Called %s PID:%u", __func__, getpid());
	retval = real_tolower(c);
	ACTIVATE();
	return retval;
}

double floor(double x)
{
	DEACTIVATE();
	double retval;
	log_debug("Called %s PID:%u", __func__, getpid());
	retval = real_floor(x);
	ACTIVATE();
	return retval;
}

float floorf(float x)
{
	DEACTIVATE();
	float retval;
	log_debug("Called %s PID:%u", __func__, getpid());
	retval = real_floorf(x);
	ACTIVATE();
	return retval;
}

double ceil(double x)
{
	DEACTIVATE();
	double retval;
	log_debug("Called %s PID:%u", __func__, getpid());
	retval = real_ceil(x);
	ACTIVATE();
	return retval;
}

int vsprintf(char *restrict s, const char *restrict fmt, va_list ap)
{
	DEACTIVATE();
	int retval;
	retval = real_vsprintf(s, fmt, ap);
	ACTIVATE();
	return retval;
}

void setbuf(FILE *restrict f, char *restrict buf)
{
	DEACTIVATE();
	real_setbuf(f, buf);
	ACTIVATE();
}

int setvbuf(FILE *restrict f, char *restrict buf, int type, size_t size)
{
	DEACTIVATE();
	int retval;
	retval = real_setvbuf(f, buf, type, size);
	ACTIVATE();
	return retval;
}

int feof(FILE *f)
{
	DEACTIVATE();
	int retval;
	retval = real_feof(f);
	ACTIVATE();
	return retval;
}

double exp(double x)
{
	DEACTIVATE();
	double retval;
	log_debug("Called %s PID:%u", __func__, getpid());
	retval = real_exp(x);
	ACTIVATE();
	return retval;
}

char *strtok(char *restrict s, const char *restrict sep)
{
	DEACTIVATE();
	char* retval;
	log_debug("Called %s PID:%u", __func__, getpid());
	retval = real_strtok(s, sep);
	ACTIVATE();
	return retval;
}

char *strncpy(char *restrict d, const char *restrict s, size_t n)
{
	DEACTIVATE();
	char* retval;
	log_debug("Called %s PID:%u", __func__, getpid());
	retval = real_strncpy(d, s, n);
	ACTIVATE();
	return retval;
}

double log(double x)
{
	DEACTIVATE();
	double retval;
	log_debug("Called %s PID:%u", __func__, getpid());
	retval = real_log(x);
	ACTIVATE();
	return retval;
}

void rewind(FILE *f)
{
	DEACTIVATE();
	real_rewind(f);
	ACTIVATE();
}

long ftell(FILE *f)
{
	DEACTIVATE();
	long retval;
	log_debug("Called %s PID:%u", __func__, getpid());
	retval = real_ftell(f);
	ACTIVATE();
	return retval;
}

void *memmove(void *dest, const void *src, size_t n)
{
	DEACTIVATE();
	void* retval;
	log_debug("Called %s PID:%u", __func__, getpid());
	retval = real_memmove(dest, src, n);
	ACTIVATE();
	return retval;
}

size_t strcspn(const char *s, const char *c)
{
	DEACTIVATE();
	size_t retval;
	log_debug("Called %s PID:%u", __func__, getpid());
	retval = real_strcspn(s, c);
	ACTIVATE();
	return retval;
}

size_t fread(void *restrict destv, size_t size, size_t nmemb, FILE *restrict f)
{
	DEACTIVATE();
	size_t retval;
	log_debug("Called %s PID:%u", __func__, getpid());
	retval = real_fread(destv, size, nmemb, f);
	ACTIVATE();
	return retval;
}

char *strcat(char *restrict dest, const char *restrict src)
{
	DEACTIVATE();
	char* retval;
	log_debug("Called %s PID:%u", __func__, getpid());
	retval = real_strcat(dest, src);
	ACTIVATE();
	return retval;
}

double difftime(time_t t1, time_t t0)
{
	DEACTIVATE();
	double retval;
	log_debug("Called %s PID:%u", __func__, getpid());
	retval = real_difftime(t1, t0);
	ACTIVATE();
	return retval;
}

char *stpcpy(char *restrict d, const char *restrict s)
{
	DEACTIVATE();
	char* retval;
	log_debug("Called %s PID:%u", __func__, getpid());
	retval = real_stpcpy(d, s);
	ACTIVATE();
	return retval;
}

void exit(int code)
{
	DEACTIVATE();
	real_exit(code);
	// Should never hit here
	while(1){}
}
