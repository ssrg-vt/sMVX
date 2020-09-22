#include "monitor.h"
#include "debug.h"
#include "ptrace.h"

static int count = 0;
/* @param: syscall num & arguments */
void pre_syscall_print(long syscall, int64_t args[])
{
	syscall_entry_t ent = syscalls[syscall];

	/* current, we want to print the syscall params */
	PRINT("(%d) %s #%ld\n", count++, syscall_name[syscall], syscall);
	
	/* printing "sensitive" syscall params. */
	if (ent.name != 0) {
		int nargs = ent.nargs;
		int i;
		PRINT("[%ld] %s (", syscall, ent.name);
		if (nargs != 0)
			RAW_PRINT("%s: 0x%lx", ent.sc_arg.arg[0], args[0]);
		for (i = 1; i < nargs; i++) {
			RAW_PRINT(", %s: 0x%lx", ent.sc_arg.arg[i], args[i]);
		}
		RAW_PRINT(")\n");
	}
}

/* @param: syscall num & return value */
void post_syscall_print(long syscall, long result)
{
//	PRINT("--------- Post Syscall Print ----------\n");
	PRINT("= %ld (0x%lx)\n\n", result, result);
}
