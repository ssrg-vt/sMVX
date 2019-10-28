#define _GNU_SOURCE
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sched.h>
#include <errno.h>
#include <sys/syscall.h>
#include <seccomp.h>
#include <sys/prctl.h>
#include <dlfcn.h>
#include <stdarg.h>
#include <stddef.h>

/* Local headers */
#include <debug.h>
#include <config.h>
#include <monitor_trampoline.h>

static int (*real_printf)(const char* restrict fmt, ...);

int printf(const char *restrict fmt, ...)
{
	real_printf("Intercepted printf!, Actual string: %s\n", fmt);
	return 1;
}

void __attribute__ ((constructor)) init_tramp(void)
{
	debug_printf("Trampoline library instantiated\n");
	real_printf = dlsym(RTLD_NEXT, "printf");
	// ensure none of our children will ever be granted more priv 
	// (via setuid, capabilities, ...)
	//prctl(PR_SET_NO_NEW_PRIVS, 1);
	//// ensure no escape is possible via ptrace
	//prctl(PR_SET_DUMPABLE, 0);

	//// Init the filter
	//scmp_filter_ctx ctx;
	//ctx = seccomp_init(SCMP_ACT_KILL); // default action: kill

	//// setup basic whitelist
	//seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0);
	//seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
	//seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
	//seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);

	//// setup our rule
	//seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(dup2),2,
	//		 SCMP_A0(SCMP_CMP_EQ,1), SCMP_A1(SCMP_CMP_EQ,2));

	//// build and load the filter
	//seccomp_load(ctx);
}

void __attribute__ ((destructor)) exit_tramp(void)
{
	//debug_printf("Trampoline library exited\n");
}
