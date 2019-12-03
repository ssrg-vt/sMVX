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
#include <stdarg.h>
#include <stddef.h>

/* Local headers */
#include <debug.h>
#include <config.h>
#include <libmonitor.h>
#include <pkey.h>
#include <syscall_blocking.h>
#include <loader.h>

/* PID of the child variant */
unsigned long mvx_child_pid = 0;

void __attribute__ ((constructor)) init_tramp(int argc, char** argv, char** env)
{
	unsigned long pkey;
	proc_info_t monitor_info, libc_info;

	/*Call this guy all the time first */
	store_original_functions();

	/* Load elf binary */
	init_loader();

	/* Always call these functions in this order because debug_printf uses
	 * real_printf */
	log_info("Trampoline library instantiated\n");

	/* Associate keys with both the monitor and libc */
	read_proc("libmonitor", &monitor_info);
	read_proc("libc", &libc_info);

	/* Allocate pkey */
	pkey = syscall(SYS_pkey_alloc, 0, 0);

	/* Associate pages of the libraries with the allocated pkey */
	associate_pkey_library(&monitor_info, pkey);
	associate_pkey_library(&libc_info, pkey);
}

void __attribute__ ((destructor)) exit_tramp(void)
{
	debug_printf("Trampoline library exited\n");
}
