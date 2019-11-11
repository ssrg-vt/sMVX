#include <monitor_trampoline.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <pkey.h>
#include <unistd.h>

#define PKEY_NO_ACCESS  (0x1)
#define PKEY_ALL_ACCESS (0x0)

/* Pkey related functions */
//void activate_pkey(unsigned long pkey)
//{
//	unsigned long pkru = (PKEY_NO_ACCESS << (2*pkey));
//	__asm__(".byte 0x0f,0x01,0xef\n\t" : : "a" (pkru), "c" (0), "d" (0));
//}
//
//void deactivate_pkey(unsigned long pkey)
//{
//	unsigned long pkru = (PKEY_ALL_ACCESS << (2*pkey));
//	__asm__(".byte 0x0f,0x01,0xef\n\t" : : "a" (pkru), "c" (0), "d" (0));
//}

inline void activate_pkey()
{
	unsigned long pkru = (PKEY_NO_ACCESS << (2*1));
	__asm__(".byte 0x0f,0x01,0xef\n\t" : : "a" (pkru), "c" (0), "d" (0));
}

inline void deactivate_pkey()
{
	unsigned long pkru = (PKEY_ALL_ACCESS << (2*1));
	__asm__(".byte 0x0f,0x01,0xef\n\t" : : "a" (pkru), "c" (0), "d" (0));
}

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
