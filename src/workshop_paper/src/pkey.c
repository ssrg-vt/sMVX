#include <libmonitor.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <pkey.h>
#include <unistd.h>

#ifdef INTEL_MPK
/* Pkey related functions */

void associate_pkey_library(proc_info_t* lib_info, unsigned long pkey)
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

#else

void associate_pkey_library(proc_info_t* lib_info, unsigned long pkey)
{
	log_warn("MPK not enabled");
}

#endif
