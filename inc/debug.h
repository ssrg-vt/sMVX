#ifndef __DEBUG__H__
#define __DEBUG__H__
#include <config.h>

extern int (*real_printf)(const char* restrict fmt, ...);

#define debug_printf(...)\
	do {if(_DEBUG) real_printf(__VA_ARGS__);} while(0)


#endif
