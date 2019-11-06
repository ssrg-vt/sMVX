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

#define PKEY_NO_ACCESS  (0x1)

static int (*real_printf)(const char* restrict fmt, ...);

/* Functions we are overriding */
int printf(const char *restrict fmt, ...)
{
	real_printf("Intercepted printf!, Actual string: %s\n", fmt);
	return 1;
}

/* Pkey related functions */
static void activate_pkey(unsigned long pkey, unsigned long access)
{
	unsigned long pkru = (access << (2*pkey));
	__asm__(".byte 0x0f,0x01,0xef\n\t" : : "a" (pkru), "c" (0), "d" (0));
}

static void associate_pkey_library(proc_info_t* lib_info, unsigned long pkey)
{
	uint64_t code_length;
	uint64_t rodata_length;
	uint64_t data_length;

	code_length	= lib_info->code_end	- lib_info->code_start;
	rodata_length	= lib_info->rodata_end	- lib_info->rodata_start;
	data_length	= lib_info->data_end	- lib_info->data_start;

	/* Protect Code Section */
	syscall(SYS_pkey_mprotect, lib_info->code_start, code_length
		, PROT_READ | PROT_EXEC, pkey);
	/* Protect ROdata Section */
	syscall(SYS_pkey_mprotect, lib_info->rodata_start, rodata_length
		, PROT_READ, pkey);
	/* Protect Data Section */
	syscall(SYS_pkey_mprotect, lib_info->data_start, data_length
		, PROT_READ | PROT_WRITE, pkey);
}

///* Enable seccomp */
//static void seccomp_enable()
//{
//	// ensure none of our children will ever be granted more priv 
//	// (via setuid, capabilities, ...)
//	prctl(PR_SET_NO_NEW_PRIVS, 1);
//	// ensure no escape is possible via ptrace
//	prctl(PR_SET_DUMPABLE, 0);
//
//	// Init the filter
//	scmp_filter_ctx ctx;
//	ctx = seccomp_init(SCMP_ACT_KILL); // default action: kill
//
//	// setup basic whitelist
//	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0);
//	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
//	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
//	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
//
//	// setup our rule
//	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(dup2),2,
//			 SCMP_A0(SCMP_CMP_EQ,1), SCMP_A1(SCMP_CMP_EQ,2));
//
//	// build and load the filter
//	seccomp_load(ctx);
//}

void __attribute__ ((constructor)) init_tramp(void)
{
	proc_info_t monitor_info, libc_info;
	unsigned long pkey;
	debug_printf("Trampoline library instantiated\n");
	//seccomp_enable();

	real_printf = dlsym(RTLD_NEXT, "printf");
	read_proc("libmonitor", &monitor_info);
	read_proc("libc", &libc_info);
	// Allocate pkey
	pkey = syscall(SYS_pkey_alloc, 0, 0);
	associate_pkey_library(&monitor_info, pkey);
	associate_pkey_library(&libc_info, pkey);
	activate_pkey(pkey, PKEY_NO_ACCESS);
}

void __attribute__ ((destructor)) exit_tramp(void)
{
	//debug_printf("Trampoline library exited\n");
}
