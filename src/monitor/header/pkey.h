#ifndef __PKEY_H__
#define __PKEY_H__
#include <monitor_trampoline.h>

//void activate_pkey(unsigned long pkey);
//void deactivate_pkey(unsigned long pkey);
void activate_pkey();
void deactivate_pkey();
void associate_pkey_library(proc_info_t* lib_info, unsigned long pkey);

#endif
