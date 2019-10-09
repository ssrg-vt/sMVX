#ifndef __DEBUG__H__
#define __DEBUG__H__
#include <config.h>

#define debug_printf(...)\
	do {if(_DEBUG) printf(__VA_ARGS__);} while(0)


#endif
