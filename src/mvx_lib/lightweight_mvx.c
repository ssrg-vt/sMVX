#define _GNU_SOURCE

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sched.h>
#include <errno.h>
#include <sys/syscall.h>

/* Local headers */
#include <debug.h>
#include <config.h>
#include <address_map.h>
#include <uthash.h>

#define LOOKUP_TABLE_SIZE	(100)
struct address_map* mapping;

struct address_map *address_hash;

//void mvx_start_hook(const char* caller_name)
//{
//	int fd;
//	char string[100];
//	char string2[100];
//	int strlen2;
//	int strlen = sprintf(string, "Return address is: %s, mmap is: %lx\n",
//		caller_name, (uint64_t)mapping);
//	fd = open("testfile.txt", O_RDWR | O_CREAT);
//	if (fd < 0)
//		return;
//	write(fd, string, strlen);
//
//	HASH_FIND_STR(address_hash, caller_name, )
//
//	/* Store into our array of mappings */
//	strncpy(mapping[current_idx].caller_name, caller_name, 50);
//	strlen2 = sprintf(string2, "What are we storing?: %s\n",
//			  mapping[current_idx].caller_name);
//	write(fd, string2, strlen);
//
//}

int __mvx_shim(void* args)
{
	/* At this point we are on a new thread. Take the args and send.*/
	debug_printf("mvx shim called \n");
	/* Call to real function should be here to insert in arguments*/
	/* What we have here is 1) Function address, 2) function arguments, but
	 * no function prototype...don't know how to call the function*/
	return 0;
}

void mvx_start_hook(const char* caller_name)
{
	struct address_map* address;
	int pid;
	void *pchild_stack = malloc(1024 * 1024);

	HASH_FIND_STR(address_hash, caller_name, address);

	/* If we found the address, we want to clone thread using it*/
	if (address)
		debug_printf("Address found is this: 0x%lx\n", address->variant_address);
		//pid = syscall(SYS_clone, (int (*) (void *))address->variant_address,
		//	    NULL, CLONE_NEWPID, NULL, NULL, NULL, NULL);
		pid = clone((int (*) (void *))__mvx_shim,
			    NULL, CLONE_NEWPID, void* {with 6 arguments}, NULL, NULL, NULL);
		debug_printf("Clone has pid %d\n", pid);
		debug_printf("errno = %d", errno);
}

void mvx_end_hook(const char* caller_name)
{
	debug_printf("mvx_end_hook called\n");
}

void __attribute__ ((constructor)) initLibrary(void)
{
	debug_printf("Lightweight mvx library instantiated\n");
	struct address_map* entry = (struct address_map*) malloc(sizeof(struct
									address_map));
	strcpy(entry->caller_name, "call_other_function");
	entry->variant_address = (uint64_t)__mvx_shim;
	HASH_ADD_STR(address_hash, caller_name, entry);
	/* mmap function lookup table */
	mapping = mmap(NULL, sizeof(struct address_map)*LOOKUP_TABLE_SIZE,
		       PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
}

void __attribute__ ((destructor)) exitLibrary(void)
{
	debug_printf("Lightweight mvx library exited\n");
	munmap(mapping, sizeof(struct address_map)*LOOKUP_TABLE_SIZE);
}
