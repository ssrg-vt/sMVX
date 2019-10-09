#ifndef __ADDRESS_MAP__H__
#define __ADDRESS_MAP__H__
#include <stdint.h>

struct address_map
{
	uint64_t original_address;
	uint64_t variant_address;
};

#endif
