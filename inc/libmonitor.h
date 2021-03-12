#ifndef __LIBMONITOR_H__
#define __LIBMONITOR_H__
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>

void store_original_functions();
int ld_preload_function(int);
void setup_ipc();
bool is_child();
bool is_parent();
void store_child_pid(unsigned long pid);
void set_mvx_active();
void associate_all_pkeys();
void clear_mvx_active();
void set_mvx_active();
extern unsigned long mvx_child_pid;
extern unsigned long mvx_parent_pid;

#endif
