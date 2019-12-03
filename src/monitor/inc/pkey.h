#ifndef __PKEY_H__
#define __PKEY_H__
#include <libmonitor.h>
#include <loader.h>
#define PKEY_NO_ACCESS  (0x1)
#define PKEY_ALL_ACCESS (0x0)

void associate_pkey_library(proc_info_t* lib_info, unsigned long pkey);

#define ACTIVATE()							       \
	do {								       \
	__asm__(".byte 0x0f,0x01,0xef\n\t" : : "a" ((PKEY_NO_ACCESS << (2*1))),\
		"c" (0), "d" (0));                                             \
	}while(0)

#define DEACTIVATE()                                                           \
	do {                                                                   \
	__asm__(".byte 0x0f,0x01,0xef\n\t" : : "a" ((PKEY_ALL_ACCESS <<        \
						      (2*1))), "c" (0), "d"    \
		 (0));                                                         \
	} while(0)

#endif
