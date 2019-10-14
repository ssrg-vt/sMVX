#ifndef __ADDRESS_MAP__H__
#define __ADDRESS_MAP__H__
#include <stdint.h>
#include <uthash.h>

struct address_map
{
	char caller_name[50];
	uint64_t variant_address;
	UT_hash_handle hh;
};

#endif
