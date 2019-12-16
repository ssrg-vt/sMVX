#include <syscall_blocking.h>
//#include <sys/prctl.h>
#include <string.h>

// Uncomment after fixing issue #13 in github
///* Enable seccomp */
//void seccomp_enable()
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
