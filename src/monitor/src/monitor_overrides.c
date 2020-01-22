/* Libc headers */
#include <dlfcn.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/stat.h>

/* Local headers */
#include <debug.h>
#include <libmonitor.h>
#include <pkey.h>
#include <loader.h>
#include <ipc.h>


/* Shared memory */
struct call_data* calldata_ptr;
struct sync_data* syncdata_ptr;

/* Real functions not being overridden */
int (*real_printf)(const char* restrict fmt, ...);
int (*real_fork)(void);
int (*real_clone)(int (*)(void *), void *, int , void *, ...);
void *(*real_malloc)(size_t);
int (*real_vfprintf)(FILE *restrict, const char *restrict, va_list);
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

/* Helper function to store the original functions we are overriding*/
void store_original_functions()
{
	if (!(real_printf	= dlsym(RTLD_NEXT, "printf")))
		log_error("printf symbol not found \n");
	if (!(real_vprintf	= dlsym(RTLD_NEXT, "vprintf")))
		log_error("vprintf symbol not found \n");
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
	if (!(real_fscanf	= dlsym(RTLD_NEXT, "fscanf")))
		log_error("fscanf symbol not found \n");
	if (!(real_fclose	= dlsym(RTLD_NEXT, "fclose")))
		log_error("fclose symbol not found \n");
	if (!(real_remove	= dlsym(RTLD_NEXT, "remove")))
		log_error("remove symbol not found \n");
	if (!(real_fputc	= dlsym(RTLD_NEXT, "fputc")))
		log_error("fputc symbol not found \n");
	if (!(real_fflush	= dlsym(RTLD_NEXT, "fflush")))
		log_error("fflush symbol not found \n");
	if (!(real_vsprintf	= dlsym(RTLD_NEXT, "vsprintf")))
		log_error("vsprintf symbol not found \n");
	if (!(real_puts		= dlsym(RTLD_NEXT, "puts")))
		log_error("puts symbol not found \n");
	if (!(real_memcpy	= dlsym(RTLD_NEXT, "memcpy")))
		log_error("memcpy symbol not found \n");
	if (!(real_free		= dlsym(RTLD_NEXT, "free")))
		log_error("free symbol not found \n");
	if (!(real_recv		= dlsym(RTLD_NEXT, "recv")))
		log_error("recv symbol not found \n");
	if (!(real_memcmp	= dlsym(RTLD_NEXT, "memcmp")))
		log_error("memcmp symbol not found \n");
	if (!(real_sendfile	= dlsym(RTLD_NEXT, "sendfile")))
		log_error("sendfile symbol not found \n");
	if (!(real_writev	= dlsym(RTLD_NEXT, "writev")))
		log_error("writev symbol not found \n");
	if (!(real_write	= dlsym(RTLD_NEXT, "write")))
		log_error("write symbol not found \n");
	if (!(real_open		= dlsym(RTLD_NEXT, "open")))
		log_error("open symbol not found \n");
	if (!(real_close	= dlsym(RTLD_NEXT, "close")))
		log_error("close symbol not found \n");
	if (!(real_epoll_pwait	= dlsym(RTLD_NEXT, "epoll_pwait")))
		log_error("epoll_pwait symbol not found \n");
	if (!(real_epoll_wait	= dlsym(RTLD_NEXT, "epoll_wait")))
		log_error("epoll_wait symbol not found \n");
	if (!(real_accept4	= dlsym(RTLD_NEXT, "accept4")))
		log_error("accept4 symbol not found \n");
	if (!(real_epoll_ctl	= dlsym(RTLD_NEXT, "epoll_ctl")))
		log_error("epoll_ctl symbol not found \n");
	if (!(real_fstat	= dlsym(RTLD_NEXT, "fstat")))
		log_error("fstat symbol not found \n");
	if (!(real_recv		= dlsym(RTLD_NEXT, "recv")))
		log_error("recv symbol not found \n");
	if (!(real_shutdown	= dlsym(RTLD_NEXT, "shutdown")))
		log_error("shutdown symbol not found \n");
	if (!(real_setsockopt	= dlsym(RTLD_NEXT, "setsockopt")))
		log_error("setsockopt symbol not found \n");
	if (!(real_gettimeofday	= dlsym(RTLD_NEXT, "gettimeofday")))
		log_error("gettimeofday symbol not found \n");
	if (!(real_localtime_r= dlsym(RTLD_NEXT, "localtime_r")))
		log_error("__localtime_r symbol not found \n");
}

///* Functions we are overriding */
//int printf(const char *restrict fmt, ...)
//{
//	DEACTIVATE();
//	va_list args;
//	va_start(args, fmt);
//	real_vprintf(fmt, args);
//	va_end(args);
//	ACTIVATE();
//	return 1;
//}
//
//int scanf(const char *restrict fmt, ...)
//{
//	DEACTIVATE();
//	va_list args;
//
//	pthread_mutex_lock(&(syncdata_ptr->monitor_mutex));
//	/* If we are a child, we wait for master to complete emulation*/
//	if (is_child()){
//		while(!calldata_ptr->ready_for_check)
//			pthread_cond_wait(&(syncdata_ptr->master_done), &(syncdata_ptr->monitor_mutex));
//
//		real_printf(calldata_ptr->em_data.buf);
//	}
//	else{
//		/* Parent, get input, perform vscanf, then emulate */
//		va_start(args, fmt);
//		vscanf(fmt, args);
//		va_end(args);
//
//		real_memcpy(&calldata_ptr->em_data.buf, fmt, strlen(fmt));
//	}
//	pthread_mutex_unlock(&(syncdata_ptr->monitor_mutex));
//	ACTIVATE();
//	return 1;
//}
//
//void *memset(void *dest, int c, size_t n)
//{
//	DEACTIVATE();
//	void* retval = real_memset(dest, c, n);
//	ACTIVATE();
//	return retval;
//}
//
//void *memcpy(void *restrict dest, const void *restrict src, size_t n)
//{
//	DEACTIVATE();
//	void* retval;
//	if(calldata_ptr->mvx_active){
//		pthread_mutex_lock(&(syncdata_ptr->monitor_mutex));
//		/* Have child check */
//		if (is_child()){
//			while(!calldata_ptr->ready_for_check)
//				pthread_cond_wait(&(syncdata_ptr->master_done), &(syncdata_ptr->monitor_mutex));
//			retval = real_memcpy(dest, src, n);
//			/* Perform retval cross-check*/
//			if ((uint64_t)retval != calldata_ptr->retval){
//				assert(false);
//			}
//			log_debug("Child is done with %s \n", __func__);
//		}
//		else{
//			retval = real_memcpy(dest, src, n);
//			/* Copy retval to shared memory */
//			calldata_ptr->retval = (uint64_t)retval;
//			calldata_ptr->ready_for_check = true;
//			log_debug("Master is done with memcpy, waiting for child\n");
//			pthread_cond_signal(&(syncdata_ptr->master_done));
//		}
//		pthread_mutex_unlock(&(syncdata_ptr->monitor_mutex));
//	}
//	else{
//		retval = real_memcpy(dest, src, n);
//	}
//	ACTIVATE();
//	return retval;
//}
//
//FILE *fopen(const char *restrict filename, const char *restrict mode)
//{
//	DEACTIVATE();
//	FILE* retval = real_fopen(filename, mode);
//	ACTIVATE();
//	return retval;
//}
//
//FILE *fopen64(const char *restrict filename, const char *restrict mode)
//{
//	DEACTIVATE();
//	FILE* retval = real_fopen(filename, mode);
//	ACTIVATE();
//	return retval;
//}
//
//FILE *fdopen(int fd, const char *mode)
//{
//	DEACTIVATE();
//	FILE* retval = real_fdopen(fd, mode);
//	ACTIVATE();
//	return retval;
//}
//
//int vfprintf(FILE *restrict f, const char *restrict fmt, va_list ap)
//{
//	DEACTIVATE();
//	int retval;
//	retval = real_vfprintf(f, fmt, ap);
//	ACTIVATE();
//	return retval;
//}
//
//int fprintf(FILE *restrict f, const char *restrict fmt, ...)
//{
//	DEACTIVATE();
//	int retval;
//	va_list args;
//	va_start(args, fmt);
//	/* Do not call real_fprintf, call vfprintff as this override is already
//	 * variadic */
//	retval = real_vfprintf(f, fmt, args);
//	va_end(args);
//	ACTIVATE();
//	return retval;
//}
//
//int sprintf(char *restrict s, const char *restrict fmt, ...)
//{
//	DEACTIVATE();
//	int retval;
//	va_list args;
//	va_start(args, fmt);
//	retval = real_vsprintf(s, fmt, args);
//	va_end(args);
//	ACTIVATE();
//	return retval;
//}
//
//int puts(const char *s)
//{
//	DEACTIVATE();
//	int retval;
//	retval = real_puts(s);
//	ACTIVATE();
//	return retval;
//}
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
//
//int fclose(FILE *f)
//{
//	DEACTIVATE();
//	int retval;
//	retval = real_fclose(f);
//	ACTIVATE();
//	return retval;
//}
//
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
//		debug_printf("We are the child process\n");
//		return pid;
//	}
//	debug_printf("Fork not implemented yet, looking into clone first.\n");
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

///* Passthrough malloc without blocking for now */
//void *malloc(size_t n)
//{
//	DEACTIVATE();
//	void* retval;
//	if(calldata_ptr->mvx_active){
//		pthread_mutex_lock(&(syncdata_ptr->monitor_mutex));
//		/* Have child check */
//		if (is_child()){
//			log_debug("Child called %s, args: size: %u\n", __func__, n);
//			retval = real_malloc(n);
//			log_debug("Child is done with %s, retval: %u\n", __func__, retval);
//		}
//		else{
//			log_debug("Master called %s, args: size: %u\n", __func__, n);
//			retval = real_malloc(n);
//			log_debug("Master is done with %s, signalling child, retval: %u\n", __func__, retval);
//		}
//		pthread_mutex_unlock(&(syncdata_ptr->monitor_mutex));
//	}
//	else{
//		//log_debug("Master called %s, mvx isn't active\n", __func__);
//		retval = real_malloc(n);
//	}
//	ACTIVATE();
//	return retval;
//}
//
//void free(void* p)
//{
//	DEACTIVATE();
//	real_free(p);
//	ACTIVATE();
//}
//
//int ld_preload_function(int i)
//{
//	DEACTIVATE();
//	debug_printf("ld_preload_function called, %d\n", i);
//	ACTIVATE();
//	return 0;
//}
//
//int fputc(int c, FILE *f)
//{
//	DEACTIVATE();
//	int retval;
//	retval = real_fputc(c, f);
//	ACTIVATE();
//	return retval;
//}
//
//int fflush(FILE *f)
//{
//	DEACTIVATE();
//	int retval;
//	retval = real_fflush(f);
//	ACTIVATE();
//	return retval;
//}
//
//ssize_t recv(int fd, void *buf, size_t len, int flags)
//{
//	DEACTIVATE();
//	ssize_t retval;
//	retval = real_recv(fd, buf, len, flags);
//	ACTIVATE();
//	return retval;
//}
//
//int memcmp(const void *vl, const void *vr, size_t n)
//{
//	DEACTIVATE();
//	int retval;
//	retval = real_memcmp(vl, vr, n);
//	ACTIVATE();
//	return retval;
//}

ssize_t sendfile(int out_fd, int in_fd, off_t *ofs, size_t count)
{
	DEACTIVATE();
	ssize_t retval;
	if(calldata_ptr->mvx_active){
		pthread_mutex_lock(&(syncdata_ptr->monitor_mutex));
		/* Have child check */
		if (is_child()){
			log_debug("Child called %s, args: out_fd %u, in_fd %u \n", __func__, out_fd, in_fd);
			while(!calldata_ptr->ready_for_check)
				pthread_cond_wait(&(syncdata_ptr->master_done), &(syncdata_ptr->monitor_mutex));
			/* Perform retval emulation */
			retval = calldata_ptr->em_data.retval;
			/* Perform offset emulation */
			real_memcpy(ofs, calldata_ptr->em_data.buf, sizeof(off_t));
			real_memset(calldata_ptr->em_data.buf, 0, sizeof(off_t));
			log_debug("Child is done with %s, retval: %u, offset: %u\n", __func__, retval, *ofs);
			calldata_ptr->ready_for_check = false;
			pthread_cond_signal(&(syncdata_ptr->follower_done));
		}
		else{
			log_debug("Master called %s, args: out_fd %u, in_fd %u \n", __func__, out_fd, in_fd);
			while(calldata_ptr->ready_for_check){
				pthread_cond_wait(&(syncdata_ptr->follower_done),
						  &(syncdata_ptr->monitor_mutex));
			}
			retval = real_sendfile(out_fd, in_fd, ofs, count);
			/* Copy retval to shared memory */
			calldata_ptr->em_data.retval = (uint64_t)retval;
			/* Copy buffer data to shared memory */
			real_memcpy(calldata_ptr->em_data.buf, ofs, sizeof(off_t));
			calldata_ptr->ready_for_check = true;
			log_debug("Master is done with %s, signalling child, retval: %u, offset: %u\n", __func__, retval,*ofs);
			pthread_cond_signal(&(syncdata_ptr->master_done));
		}
		pthread_mutex_unlock(&(syncdata_ptr->monitor_mutex));
	}
	else{
		log_debug("Master called %s, mvx isn't active, PID:%u\n", __func__, getpid());
		retval = real_sendfile(out_fd, in_fd, ofs, count);
	}
	ACTIVATE();
	return retval;
}

ssize_t writev(int fd, const struct iovec *iov, int count)
{
	DEACTIVATE();
	ssize_t retval;
	if(calldata_ptr->mvx_active){
		pthread_mutex_lock(&(syncdata_ptr->monitor_mutex));
		/* Have child check */
		if (is_child()){
			log_debug("Child called %s, arguments:fd %u, count %u\n", __func__, fd, count);
			while(!calldata_ptr->ready_for_check)
				pthread_cond_wait(&(syncdata_ptr->master_done), &(syncdata_ptr->monitor_mutex));
			/* Perform retval emulation */
			retval = calldata_ptr->em_data.retval;
			log_debug("Child is done with %s \n", __func__);
			calldata_ptr->ready_for_check = false;
			pthread_cond_signal(&(syncdata_ptr->follower_done));
		}
		else{
			log_debug("Master called %s, arguments: fd %u, count %u\n", __func__, fd, count);
			while(calldata_ptr->ready_for_check)
				pthread_cond_wait(&(syncdata_ptr->follower_done),
						  &(syncdata_ptr->monitor_mutex));
			retval = real_writev(fd, iov, count);
			/* Copy retval to shared memory */
			calldata_ptr->em_data.retval = (uint64_t)retval;
			calldata_ptr->ready_for_check = true;
			log_debug("Master is done with %s, signalling child\n",
				  __func__);
			pthread_cond_signal(&(syncdata_ptr->master_done));
		}
		pthread_mutex_unlock(&(syncdata_ptr->monitor_mutex));
	}
	else{
		log_debug("Master called %s, mvx isn't active, PID:%u\n", __func__, getpid());
		retval = real_writev(fd, iov, count);
	}
	ACTIVATE();
	return retval;
}

ssize_t write(int fd, const void *buf, size_t count)
{
	DEACTIVATE();
	ssize_t retval;
	if(calldata_ptr->mvx_active){
		pthread_mutex_lock(&(syncdata_ptr->monitor_mutex));
		/* Have child check */
		if (is_child()){
			log_debug("Child called %s, arguments:fd %u, count %u\n", __func__, fd, count);
			log_debug("Child says Buffer is: %s\n", (char*)buf);
			while(!calldata_ptr->ready_for_check)
				pthread_cond_wait(&(syncdata_ptr->master_done), &(syncdata_ptr->monitor_mutex));
			/* Perform retval emulation */
			retval = calldata_ptr->em_data.retval;
			log_debug("Child is done with %s \n", __func__);
			calldata_ptr->ready_for_check = false;
			pthread_cond_signal(&(syncdata_ptr->follower_done));
		}
		else{
			log_debug("Master called %s, arguments: fd %u, count %u\n", __func__, fd, count);
			log_debug("Master says Buffer is: %s\n", (char*)buf);
			while(calldata_ptr->ready_for_check )
				pthread_cond_wait(&(syncdata_ptr->follower_done),
						  &(syncdata_ptr->monitor_mutex));
			retval = real_write(fd, buf, count);
			/* Copy retval to shared memory */
			calldata_ptr->em_data.retval = (uint64_t)retval;
			calldata_ptr->ready_for_check = true;
			log_debug("Master is done with %s, signalling child\n", __func__);
			pthread_cond_signal(&(syncdata_ptr->master_done));
		}
		pthread_mutex_unlock(&(syncdata_ptr->monitor_mutex));
	}
	else{
		log_debug("Master called %s, mvx isn't active, PID:%u\n", __func__, getpid());
		retval = real_write(fd, buf, count);
	}
	ACTIVATE();
	return retval;
}

int open(const char *filename, int flags, ...)
{
	DEACTIVATE();
	unsigned mode = 0;
	int retval;
	if(calldata_ptr->mvx_active){
		pthread_mutex_lock(&(syncdata_ptr->monitor_mutex));
		/* Have child check */
		if (is_child()){
			log_debug("Child called %s, filename: %s\n", __func__, filename);
			while(!calldata_ptr->ready_for_check)
				pthread_cond_wait(&(syncdata_ptr->master_done), &(syncdata_ptr->monitor_mutex));
			/* Perform retval emulation */
			retval = calldata_ptr->em_data.retval;
			calldata_ptr->ready_for_check = false;
			log_debug("Child is done with %s, ready for check is: %u\n", __func__, calldata_ptr->ready_for_check);
			pthread_cond_signal(&(syncdata_ptr->follower_done));
		}
		else{
			log_debug("Master called %s, filename: %s\n", __func__, filename);
			while(calldata_ptr->ready_for_check )
				pthread_cond_wait(&(syncdata_ptr->follower_done),
						  &(syncdata_ptr->monitor_mutex));
			if ((flags & O_CREAT) || (flags & O_TMPFILE) == O_TMPFILE) {
				va_list ap;
				va_start(ap, flags);
				mode = va_arg(ap, mode_t);
				va_end(ap);
				retval = real_open(filename, flags, mode);
			}
			else {
				retval = real_open(filename, flags);
			}

			/* Copy retval to shared memory */
			calldata_ptr->em_data.retval = (uint64_t)retval;
			calldata_ptr->ready_for_check = true;

			pthread_cond_signal(&(syncdata_ptr->master_done));
			log_debug("Master is done with %s, signalling child\n",
				  __func__);
		}
		pthread_mutex_unlock(&(syncdata_ptr->monitor_mutex));
	}
	else{
		log_debug("Master called %s, mvx isn't active, PID:%u\n", __func__, getpid());
		if ((flags & O_CREAT) || (flags & O_TMPFILE) == O_TMPFILE) {
			va_list ap;
			va_start(ap, flags);
			mode = va_arg(ap, mode_t);
			va_end(ap);
			retval = real_open(filename, flags, mode);
		}
		else {
			retval = real_open(filename, flags);
		}
	}
	ACTIVATE();
	return retval;
}

int close(int fd)
{
	DEACTIVATE();
	int retval;
	if(calldata_ptr->mvx_active){
		pthread_mutex_lock(&(syncdata_ptr->monitor_mutex));
		/* Have child check */
		if (is_child()){
			log_debug("Child called %s, fd is: %u\n", __func__, fd);
			while(!calldata_ptr->ready_for_check)
				pthread_cond_wait(&(syncdata_ptr->master_done), &(syncdata_ptr->monitor_mutex));
			/* Perform retval emulation */
			retval = calldata_ptr->em_data.retval;
			log_debug("Child is done with %s \n", __func__);
			calldata_ptr->ready_for_check = false;
			pthread_cond_signal(&(syncdata_ptr->follower_done));
		}
		else{
			log_debug("Master called %s, fd is: %u\n", __func__, fd);
			while(calldata_ptr->ready_for_check )
				pthread_cond_wait(&(syncdata_ptr->follower_done),
						  &(syncdata_ptr->monitor_mutex));
			retval = real_close(fd);
			/* Copy retval to shared memory */
			calldata_ptr->em_data.retval = (uint64_t)retval;
			calldata_ptr->ready_for_check = true;
			pthread_cond_signal(&(syncdata_ptr->master_done));
			log_debug("Master is done with %s, signalling child\n",
				  __func__);
		}
		pthread_mutex_unlock(&(syncdata_ptr->monitor_mutex));
	}
	else{
		log_debug("Master called %s, mvx isn't active, PID:%u\n", __func__, getpid());
		retval = real_close(fd);
	}
	ACTIVATE();
	return retval;
}

int epoll_pwait(int fd, struct epoll_event *ev, int cnt, int to, const sigset_t *sigs)
{
	DEACTIVATE();
	int retval;
	if(calldata_ptr->mvx_active){
		pthread_mutex_lock(&(syncdata_ptr->monitor_mutex));
		/* Have child check */
		if (is_child()){
			log_debug("Child called %s\n", __func__);
			while(!calldata_ptr->ready_for_check)
				pthread_cond_wait(&(syncdata_ptr->master_done), &(syncdata_ptr->monitor_mutex));
			/* Perform retval emulation */
			retval = calldata_ptr->em_data.retval;
			log_debug("Child is done with %s \n", __func__);
			calldata_ptr->ready_for_check = false;
			pthread_cond_signal(&(syncdata_ptr->follower_done));
		}
		else{
			log_debug("Master called %s\n", __func__);
			while(calldata_ptr->ready_for_check )
				pthread_cond_wait(&(syncdata_ptr->follower_done),
						  &(syncdata_ptr->monitor_mutex));
			retval = real_epoll_pwait(fd, ev, cnt, to, sigs);
			/* Copy retval to shared memory */
			calldata_ptr->em_data.retval = (uint64_t)retval;
			calldata_ptr->ready_for_check = true;
			pthread_cond_signal(&(syncdata_ptr->master_done));
			log_debug("Master is done with %s, signalling child\n",
				  __func__);
		}
		pthread_mutex_unlock(&(syncdata_ptr->monitor_mutex));
	}
	else{
		log_debug("Master called %s, mvx isn't active, PID:%u\n", __func__, getpid());
		retval = real_epoll_pwait(fd, ev, cnt, to, sigs);
	}
	ACTIVATE();
	return retval;
}

int epoll_wait(int fd, struct epoll_event *ev, int cnt, int to)
{
	DEACTIVATE();
	int retval;
	if(calldata_ptr->mvx_active){
		pthread_mutex_lock(&(syncdata_ptr->monitor_mutex));
		/* Have child check */
		if (is_child()){
			log_debug("Child called %s\n", __func__);
			while(!calldata_ptr->ready_for_check)
				pthread_cond_wait(&(syncdata_ptr->master_done), &(syncdata_ptr->monitor_mutex));
			/* Perform retval emulation */
			retval = calldata_ptr->em_data.retval;
			/* Perform ev emulation */
			real_memcpy(ev, calldata_ptr->em_data.buf, sizeof(struct
									  epoll_event));
			real_memset(calldata_ptr->em_data.buf, 0, sizeof(struct
									 epoll_event));
			log_debug("Child is done with %s \n", __func__);
			calldata_ptr->ready_for_check = false;
			pthread_cond_signal(&(syncdata_ptr->follower_done));
		}
		else{
			log_debug("Master called %s\n", __func__);
			while(calldata_ptr->ready_for_check )
				pthread_cond_wait(&(syncdata_ptr->follower_done),
						  &(syncdata_ptr->monitor_mutex));
			retval = real_epoll_wait(fd, ev, cnt, to);
			/* Copy retval to shared memory */
			calldata_ptr->em_data.retval = (uint64_t)retval;
			/* Copy buffer data to shared memory */
			real_memcpy(calldata_ptr->em_data.buf, ev, sizeof(struct
									  epoll_event));
			calldata_ptr->ready_for_check = true;
			pthread_cond_signal(&(syncdata_ptr->master_done));
			log_debug("Master is done with %s, signalling child\n",
				  __func__);
		}
		pthread_mutex_unlock(&(syncdata_ptr->monitor_mutex));
	}
	else{
		log_debug("Master called %s, mvx isn't active, PID:%u\n", __func__, getpid());
		retval = real_epoll_wait(fd, ev, cnt, to);
	}
	ACTIVATE();
	return retval;
}

int accept4(int fd, struct sockaddr *restrict addr, socklen_t *restrict len, int flg)
{
	DEACTIVATE();
	int retval;
	if(calldata_ptr->mvx_active){
		pthread_mutex_lock(&(syncdata_ptr->monitor_mutex));
		/* Have child check */
		if (is_child()){
			log_debug("Child called %s\n", __func__);
			while(!calldata_ptr->ready_for_check)
				pthread_cond_wait(&(syncdata_ptr->master_done), &(syncdata_ptr->monitor_mutex));
			/* Perform retval emulation */
			retval = calldata_ptr->em_data.retval;
			log_debug("Child is done with %s \n", __func__);
			calldata_ptr->ready_for_check = false;
			pthread_cond_signal(&(syncdata_ptr->follower_done));
		}
		else{
			log_debug("Master called %s\n", __func__);
			while(calldata_ptr->ready_for_check )
				pthread_cond_wait(&(syncdata_ptr->follower_done),
						  &(syncdata_ptr->monitor_mutex));
			retval = real_accept4(fd, addr, len, flg);
			/* Copy retval to shared memory */
			calldata_ptr->em_data.retval = (uint64_t)retval;
			calldata_ptr->ready_for_check = true;
			pthread_cond_signal(&(syncdata_ptr->master_done));
			log_debug("Master is done with %s, signalling child\n",
				  __func__);
		}
		pthread_mutex_unlock(&(syncdata_ptr->monitor_mutex));
	}
	else{
		log_debug("Master called %s, mvx isn't active, PID:%u\n", __func__, getpid());
		retval = real_accept4(fd, addr, len, flg);
	}
	ACTIVATE();
	return retval;
}

int epoll_ctl(int fd, int op, int fd2, struct epoll_event *ev)
{
	DEACTIVATE();
	int retval;
	if(calldata_ptr->mvx_active){
		pthread_mutex_lock(&(syncdata_ptr->monitor_mutex));
		/* Have child check */
		if (is_child()){
			log_debug("Child called %s\n", __func__);
			while(!calldata_ptr->ready_for_check)
				pthread_cond_wait(&(syncdata_ptr->master_done), &(syncdata_ptr->monitor_mutex));
			/* Perform retval emulation */
			retval = calldata_ptr->em_data.retval;
			log_debug("Child is done with %s \n", __func__);
			calldata_ptr->ready_for_check = false;
			pthread_cond_signal(&(syncdata_ptr->follower_done));
		}
		else{
			log_debug("Master called %s\n", __func__);
			while(calldata_ptr->ready_for_check )
				pthread_cond_wait(&(syncdata_ptr->follower_done),
						  &(syncdata_ptr->monitor_mutex));
			retval = real_epoll_ctl(fd, op ,fd2, ev);
			/* Copy retval to shared memory */
			calldata_ptr->em_data.retval = (uint64_t)retval;
			calldata_ptr->ready_for_check = true;
			pthread_cond_signal(&(syncdata_ptr->master_done));
			log_debug("Master is done with %s, signalling child\n",
				  __func__);
		}
		pthread_mutex_unlock(&(syncdata_ptr->monitor_mutex));
	}
	else{
		log_debug("Master called %s, mvx isn't active, PID:%u\n", __func__, getpid());
		retval = real_epoll_ctl(fd, op ,fd2, ev);
	}
	ACTIVATE();
	return retval;
}

int fstat(int fd, struct stat *st)
{
	DEACTIVATE();
	int retval;
	if(calldata_ptr->mvx_active){
		pthread_mutex_lock(&(syncdata_ptr->monitor_mutex));
		/* Have child check */
		if (is_child()){
			log_debug("Child called %s\n", __func__);
			while(!calldata_ptr->ready_for_check){
				pthread_cond_wait(&(syncdata_ptr->master_done), &(syncdata_ptr->monitor_mutex));
			}
			/* Perform retval emulation */
			retval = calldata_ptr->em_data.retval;
			/* Perform stat emulation */
			real_memcpy(st, calldata_ptr->em_data.buf, sizeof(struct
									  stat));
			real_memset(calldata_ptr->em_data.buf, 0, sizeof(struct
									 stat));
			log_debug("Child is done with %s , mode: %u\n",__func__, st->st_mode);
			calldata_ptr->ready_for_check = false;
			pthread_cond_signal(&(syncdata_ptr->follower_done));
		}
		else{
			log_debug("Master called %s\n", __func__);
			while(calldata_ptr->ready_for_check ){
				pthread_cond_wait(&(syncdata_ptr->follower_done),
						  &(syncdata_ptr->monitor_mutex));
			}
			retval = real_fstat(fd, st);
			/* Copy retval to shared memory */
			calldata_ptr->em_data.retval = (uint64_t)retval;
			/* Copy buffer data to shared memory */
			real_memcpy(calldata_ptr->em_data.buf, st, sizeof(struct
									  stat));

			calldata_ptr->ready_for_check = true;
			pthread_cond_signal(&(syncdata_ptr->master_done));
			log_debug("Master is done with %s , mode: %u\n",__func__, st->st_mode);
		}
		pthread_mutex_unlock(&(syncdata_ptr->monitor_mutex));
	}
	else{
		log_debug("Master called %s, mvx isn't active, PID:%u\n", __func__, getpid());
		retval = real_fstat(fd, st);
	}
	ACTIVATE();
	return retval;
}

ssize_t recv(int fd, void *buf, size_t len, int flags)
{
	DEACTIVATE();
	int retval;
	if(calldata_ptr->mvx_active){
		pthread_mutex_lock(&(syncdata_ptr->monitor_mutex));
		/* Have child check */
		if (is_child()){
			log_debug("Child called %s, args: fd %u, len %u\n", __func__, fd, len);
			while(!calldata_ptr->ready_for_check)
				pthread_cond_wait(&(syncdata_ptr->master_done), &(syncdata_ptr->monitor_mutex));
			/* Perform retval emulation */
			retval = calldata_ptr->em_data.retval;
			/* Errno emulation */
			errno =  calldata_ptr->em_data.err;
			/* Perform buf emulation */
			real_memcpy(buf, calldata_ptr->em_data.buf, len);
			real_memset(calldata_ptr->em_data.buf, 0, len);
			//log_debug("Child is done with %s, retval: %u, buf:%s\n", __func__, retval, buf);
			calldata_ptr->ready_for_check = false;
			pthread_cond_signal(&(syncdata_ptr->follower_done));
		}
		else{
			log_debug("Master called %s, args: fd %u, len %u\n", __func__, fd, len);
			while(calldata_ptr->ready_for_check )
				pthread_cond_wait(&(syncdata_ptr->follower_done),
						  &(syncdata_ptr->monitor_mutex));
			retval = real_recv(fd, buf, len, flags);
			/* Copy retval to shared memory */
			calldata_ptr->em_data.retval = (uint64_t)retval;
			/* Copy system errno */
			calldata_ptr->em_data.err = errno;
			/* Copy buffer data to shared memory */
			real_memcpy(calldata_ptr->em_data.buf, buf, len);

			calldata_ptr->ready_for_check = true;
			pthread_cond_signal(&(syncdata_ptr->master_done));
			//log_debug("Master is done with %s, retval: %u, buf:%s\n", __func__, retval, buf);
		}
		pthread_mutex_unlock(&(syncdata_ptr->monitor_mutex));
	}
	else{
		log_debug("Master called %s, mvx isn't active, PID:%u\n", __func__, getpid());
		retval = real_recv(fd, buf, len, flags);
	}
	ACTIVATE();
	return retval;
}

int shutdown(int fd, int how)
{
	DEACTIVATE();
	int retval;
	if(calldata_ptr->mvx_active){
		pthread_mutex_lock(&(syncdata_ptr->monitor_mutex));
		/* Have child check */
		if (is_child()){
			log_debug("Child called %s, args: fd %u, how %u\n", __func__, fd, how);
			while(!calldata_ptr->ready_for_check)
				pthread_cond_wait(&(syncdata_ptr->master_done), &(syncdata_ptr->monitor_mutex));
			/* Perform retval emulation */
			retval = calldata_ptr->em_data.retval;
			log_debug("Child is done with %s, retval: %u\n", __func__, retval);
			calldata_ptr->ready_for_check = false;
			pthread_cond_signal(&(syncdata_ptr->follower_done));
		}
		else{
			log_debug("Master called %s, args: fd %u, how %u\n", __func__, fd, how);
			while(calldata_ptr->ready_for_check )
				pthread_cond_wait(&(syncdata_ptr->follower_done),
						  &(syncdata_ptr->monitor_mutex));
			retval = real_shutdown(fd, how);
			/* Copy retval to shared memory */
			calldata_ptr->em_data.retval = (uint64_t)retval;
			calldata_ptr->ready_for_check = true;
			pthread_cond_signal(&(syncdata_ptr->master_done));
			log_debug("Master is done with %s, signalling child, retval: %u\n", __func__, retval);
		}
		pthread_mutex_unlock(&(syncdata_ptr->monitor_mutex));
	}
	else{
		log_debug("Master called %s, mvx isn't active, PID:%u\n", __func__, getpid());
		retval = real_shutdown(fd, how);
	}
	ACTIVATE();
	return retval;
}

int setsockopt(int fd, int level, int optname, const void *optval, socklen_t optlen)
{
	DEACTIVATE();
	int retval;
	if(calldata_ptr->mvx_active){
		pthread_mutex_lock(&(syncdata_ptr->monitor_mutex));
		/* Have child check */
		if (is_child()){
			log_debug("Child called %s, args: fd %u, level %u\n", __func__, fd, level);
			while(!calldata_ptr->ready_for_check)
				pthread_cond_wait(&(syncdata_ptr->master_done), &(syncdata_ptr->monitor_mutex));
			/* Perform retval emulation */
			retval = calldata_ptr->em_data.retval;
			log_debug("Child is done with %s, retval: %u\n", __func__, retval);
			calldata_ptr->ready_for_check = false;
			pthread_cond_signal(&(syncdata_ptr->follower_done));
		}
		else{
			log_debug("Master called %s, args: fd %u, level %u\n", __func__, fd, level);
			while(calldata_ptr->ready_for_check )
				pthread_cond_wait(&(syncdata_ptr->follower_done),
						  &(syncdata_ptr->monitor_mutex));
			retval = real_setsockopt(fd, level, optname, optval,
						 optlen);
			/* Copy retval to shared memory */
			calldata_ptr->em_data.retval = (uint64_t)retval;
			calldata_ptr->ready_for_check = true;
			pthread_cond_signal(&(syncdata_ptr->master_done));
			log_debug("Master is done with %s, signalling child, retval: %u\n", __func__, retval);
		}
		pthread_mutex_unlock(&(syncdata_ptr->monitor_mutex));
	}
	else{
		log_debug("Master called %s, mvx isn't active, PID:%u\n", __func__, getpid());
		retval = real_setsockopt(fd, level, optname, optval,
						 optlen);
	}
	ACTIVATE();
	return retval;
}
//
//int gettimeofday(struct timeval *restrict tv, void *restrict tz)
//{
//	DEACTIVATE();
//	int retval;
//	if(calldata_ptr->mvx_active){
//		pthread_mutex_lock(&(syncdata_ptr->monitor_mutex));
//		/* Have child check */
//		if (is_child()){
//			log_debug("Child called %s\n", __func__);
//			while(!calldata_ptr->ready_for_check)
//				pthread_cond_wait(&(syncdata_ptr->master_done), &(syncdata_ptr->monitor_mutex));
//			/* Perform retval emulation */
//			retval = calldata_ptr->em_data.retval;
//			/* Perform buf emulation */
//			real_memcpy(tv, calldata_ptr->em_data.buf, sizeof(struct
//									  timeval));
//			real_memset(calldata_ptr->em_data.buf, 0, sizeof(struct
//									 timeval));
//			log_debug("Child is done with %s, retval: %u\n", __func__, retval);
//			calldata_ptr->ready_for_check = false;
//			pthread_cond_signal(&(syncdata_ptr->follower_done));
//		}
//		else{
//			log_debug("Master called %s\n", __func__);
//			while(calldata_ptr->ready_for_check )
//				pthread_cond_wait(&(syncdata_ptr->follower_done),
//						  &(syncdata_ptr->monitor_mutex));
//			retval = real_gettimeofday(tv, tz);
//			/* Copy retval to shared memory */
//			calldata_ptr->em_data.retval = (uint64_t)retval;
//			/* Copy buffer data to shared memory */
//			real_memcpy(calldata_ptr->em_data.buf, tv, sizeof(struct
//									  timeval));
//
//			calldata_ptr->ready_for_check = true;
//			pthread_cond_signal(&(syncdata_ptr->master_done));
//			log_debug("Master is done with %s, signalling child, retval: %u\n", __func__, retval);
//		}
//		pthread_mutex_unlock(&(syncdata_ptr->monitor_mutex));
//	}
//	else{
//		log_debug("Master called %s, mvx isn't active, PID:%u\n", __func__, getpid());
//		retval = real_gettimeofday(tv, tz);
//	}
//	ACTIVATE();
//	return retval;
//}

struct tm *localtime_r(const time_t *restrict t, struct tm *restrict tm)
{
	DEACTIVATE();
	struct tm* retval;
	if(calldata_ptr->mvx_active){
		pthread_mutex_lock(&(syncdata_ptr->monitor_mutex));
		/* Have child check */
		if (is_child()){
			log_debug("Child called %s\n", __func__);
			while(!calldata_ptr->ready_for_check)
				pthread_cond_wait(&(syncdata_ptr->master_done), &(syncdata_ptr->monitor_mutex));
			/* Perform retval emulation */
			retval = (struct tm*)calldata_ptr->em_data.retval;
			/* Perform buf emulation */
			real_memcpy(tm, calldata_ptr->em_data.buf, sizeof(struct
									  tm));
			real_memset(calldata_ptr->em_data.buf, 0, sizeof(struct
									 tm));
			log_debug("Child is done with %s, retval: %u\n", __func__, retval);
			calldata_ptr->ready_for_check = false;
			pthread_cond_signal(&(syncdata_ptr->follower_done));
		}
		else{
			log_debug("Master called %s\n", __func__);
			while(calldata_ptr->ready_for_check )
				pthread_cond_wait(&(syncdata_ptr->follower_done),
						  &(syncdata_ptr->monitor_mutex));
			retval = real_localtime_r(t, tm);
			/* Copy retval to shared memory */
			calldata_ptr->em_data.retval = (uint64_t)retval;
			/* Copy buffer data to shared memory */
			real_memcpy(calldata_ptr->em_data.buf, tm, sizeof(struct
									  tm));

			calldata_ptr->ready_for_check = true;
			pthread_cond_signal(&(syncdata_ptr->master_done));
			log_debug("Master is done with %s, signalling child, retval: %u\n", __func__, retval);
		}
		pthread_mutex_unlock(&(syncdata_ptr->monitor_mutex));
	}
	else{
		log_debug("Master called %s, mvx isn't active, PID:%u\n", __func__, getpid());
		retval = real_localtime_r(t, tm);
	}
	ACTIVATE();
	return retval;
}
