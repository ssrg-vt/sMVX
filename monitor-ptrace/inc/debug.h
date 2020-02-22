#ifndef _DEBUG_H
#define _DEBUG_H

#include <stdio.h>	// stderr
#include <stdlib.h>	// EXIT_FAILURE
#include <assert.h>	// assert()

#include "config.h"	// _DEBUG

/**
 * The DEBUG mode print functions.
 * */
#ifdef _DEBUG
#define FATAL(...) \
    do { \
        fprintf(stderr, "[MVX Fatal]: " __VA_ARGS__); \
        fputc('\n', stderr); \
        exit(EXIT_FAILURE); \
    } while (0);

#define ERROR(...) \
	do { \
		fprintf(stderr, "[MVX Error]: "__VA_ARGS__); \
		fputc('\n', stderr); \
	} while(0);

#define PRINT(...) \
    do { \
	fprintf(stdout, "[MVX]: " __VA_ARGS__); \
	fflush(stdout); \
    } while (0);

#define RAW_PRINT(...) \
    do { \
	fprintf(stdout, __VA_ARGS__); \
	fflush(stdout); \
    } while (0);
#else	// ifdef _DEBUG
#define FATAL(...)	do {} while(0)
#define ERROR(...)	do {} while(0)
#define PRINT(...)	do {} while(0)
#define RAW_PRINT(...)	do {} while(0)
#endif	// end _DEBUG

/**
 * Debug mode print message for message layer.
 * */
//#define _MSG_DEBUG
#ifdef _MSG_DEBUG
#define MSG_PRINT(...) \
    do { \
	fprintf(stdout, "[MVX Msg]: " __VA_ARGS__); \
	fflush(stdout); \
    } while (0);
#else	// ifdef _MSG_DEBUG
#define MSG_PRINT(...)	do {} while(0);
#endif	// end	_MSG_DEBUG

/**
 * Debug mode print message for virtual fd.
 * */
//#define _VFD_DEBUG
#ifdef _VFD_DEBUG
#define VFD_PRINT(...) \
    do { \
	fprintf(stdout, "[MVX VFD]: " __VA_ARGS__); \
	fflush(stdout); \
    } while (0);
#else	// ifdef _VFD_DEBUG
#define VFD_PRINT(...)	do {} while(0);
#endif	// end	_VFD_DEBUG

#define _ASSERT
#ifdef _ASSERT
#define mvx_assert(expr, ...) \
    do { \
	if (!(expr)) fprintf(stdout, "[MVX Assert]: " __VA_ARGS__); \
	assert(expr); \
    } while(0);
#else
#define mvx_assert(expr, ...) do {} while(0);
#endif

#endif	// _DEBUG_H
