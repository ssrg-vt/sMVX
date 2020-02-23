#ifndef __LIBMONITOR_H__
#define __LIBMONITOR_H__
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdio.h>

void store_original_functions();
void store_child_pid(unsigned long pid);
void associate_all_pkeys();
extern char *(*real_getenv)(const char *name);
extern int (*real_strcmp)(const char *l, const char *r);
extern int (*real_fprintf)(FILE *restrict f, const char *restrict fmt, ...);
extern int (*real_vfprintf)(FILE *restrict, const char *restrict, va_list);
extern int (*real_fflush)(FILE *f);
extern char *(*real_strstr)(const char *h, const char *n);
extern int (*real_sscanf)(const char *restrict s, const char *restrict fmt, ...);
extern FILE *(*real_fopen)(const char *restrict filename, const char *restrict mode);
extern int (*real_fclose)(FILE *f);
extern char *(*real_fgets)(char *restrict s, int n, FILE *restrict f);
extern pid_t (*real_getpid)(void);

#endif
