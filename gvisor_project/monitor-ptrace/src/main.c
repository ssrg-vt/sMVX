#define _POSIX_C_SOURCE 200112L

/* C standard library */
#include <errno.h>		// errno
#include <stdio.h>		// pid_t
#include <stddef.h>
#include <stdlib.h>		// EXIT_FAILURE
#include <string.h>

/* POSIX */
#include <unistd.h>
#include <signal.h>		// SIGTRAP
#include <sys/user.h>	// struct user_regs_struct
#include <sys/wait.h>
#include <time.h>		// struct timespec, clock_gettime()

/* Linux */
#include <syscall.h>
#include <sys/ptrace.h>

#include <linux/ptrace.h>
#include <sys/reg.h>	// ORIG_RAX

#include "debug.h"		// FATAL & PRINT
#include "ptrace.h"
#include "monitor.h"
#include "common.h"		// likely, unlikely
#include "config.h"		// IP_SERVER

/* Time measuring. */
struct timespec tstart={0,0}, tend={0,0};

/**
 * Main function for multi-ISA MVX
 * Use: ./mvx_monitor <executable> <args>
 * */
int main(int argc, char **argv)
{
	if (argc <= 1)
	    FATAL("too few arguments: %d", argc);

	clock_gettime(CLOCK_MONOTONIC, &tstart);
	pid_t pid = fork();
	switch (pid) {
		case -1: /* error */
			FATAL("%s. pid -1", strerror(errno));
		case 0:  /* child, executing the tracee */
			ptrace(PTRACE_TRACEME, 0, 0, 0);
			execvp(argv[1], argv + 1);
			FATAL("%s. child", strerror(errno));
	}

	waitpid(pid, 0, 0);	// sync with PTRACE_TRACEME
	ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_EXITKILL);

	int terminate = 0;
	int status = 0;
	while (!terminate) {
		/* Enter next system call (before entering the kernel) */
		status = 0;
		if (ptrace_syscall_status(pid, &status) < 0)
			FATAL("PTRACE_SYSCALL error 1: %s.", strerror(errno));

		/* Handles syscall params. */
		struct user_regs_struct regs;
		int64_t args[6];
		int64_t syscall_retval;
		uint64_t syscall_num;
		/* Get system call arguments */
		syscall_num = get_regs_args(pid, &regs, args);
//		pre_syscall_print(syscall_num, args);

		/* Run system call and stop on exit (after syscall return) */
		if (ptrace_syscall(pid) < 0)
			FATAL("PTRACE_SYSCALL error 2: %s.", strerror(errno));

		/* Handles syscall retval. */
		syscall_retval = get_retval(pid, &regs, &terminate);
		if (terminate) {
			PRINT("syscall #%ld, ret %ld. terminate\n",
			      syscall_num, syscall_retval);
			break;
		}
//		post_syscall_print(syscall_num, syscall_retval);
	}
	clock_gettime(CLOCK_MONOTONIC, &tend);
	printf("%.5f seconds\n", ((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) - 
           ((double)tstart.tv_sec + 1.0e-9*tstart.tv_nsec));
	PRINT("Finish main loop!\n");
}
