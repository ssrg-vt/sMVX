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
#include <dlfcn.h>
#include <stdarg.h>
#include <stddef.h>

/* Local headers */
#include <debug.h>
#include <config.h>
#include <monitor_trampoline.h>
#include <pkey.h>
#include <syscall_blocking.h>

/**
 * Read /proc/self/maps, find out the code/data locations
 * */
int read_proc(const char *bin_name, proc_info_t *pinfo)
{
	FILE * fproc;
	char line[512];
	char flag[8];
	uint64_t start, end;
	uint32_t file_offset, dev_major, dev_minor, inode;

	fproc = fopen("/proc/self/maps", "r");
	while (fgets(line, 511, fproc) != NULL) {
		sscanf(line, "%lx-%lx %31s %x %x:%x %u", &start, &end, flag, 
				&file_offset, &dev_major, &dev_minor, &inode);
		if (strstr(line, bin_name)) {
			if (!strcmp(flag, "r-xp")) {
				pinfo->code_start = start;
				pinfo->code_end = end;
			}
			if (!strcmp(flag, "r--p")) {
				pinfo->rodata_start = start;
				pinfo->rodata_end = end;
			}
			if (!strcmp(flag, "rw-p")) {
				pinfo->data_start = start;
				pinfo->data_end = end;
			}
		}
	}
	fclose(fproc);

	return 0;
}

void __attribute__ ((constructor)) init_tramp(void)
{
	proc_info_t monitor_info, libc_info;

	/* Always register printf in this order */
	real_printf = dlsym(RTLD_NEXT, "printf");
	debug_printf("Trampoline library instantiated\n");

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
