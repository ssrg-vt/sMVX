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
#include <lightweight_mvx.h>
#define PKEY_DISABLE_ACCESS 	(0x1)
#define LOOKUP_TABLE_SIZE	(100)
struct address_map* mapping;

struct address_map *address_hash;
void* pchild_stack;

int global_var = 0;

int cloned_function(int test, char* ptr)
{
	printf("Test is : %d, ptr to string is: %s\n", test, ptr);
	return 0;
}

void test_function()
{
	int i = 256;
	printf("Test function called: %d \n", i);
}

static int __mvx_shim(void* args)
{
	/* At this point we are on a new thread. Take the args and send.*/
	struct shim_arguments* params = (struct shim_arguments*)args;
	/* Unpack arguments */
	switch (params->num_args){
		case 0:
			goto zero;
			break;
		case 1:
			goto one;
			break;
		case 2:
			goto two;
			break;
		case 3:
			goto three;
			break;
		case 4:
			goto four;
			break;
		case 5:
			goto five;
			break;
		case 6:
			goto six;
			break;
	}

six:
	__asm__ __volatile__(
		"mov %0, %%r9" : : "g"(params->arg5)
	);
five:
	__asm__ __volatile__(
		"mov %0, %%r8" : : "g"(params->arg4)
	);
four:
	__asm__ __volatile__(
		"mov %0, %%rcx" : : "g"(params->arg3)
	);
three:
	__asm__ __volatile__(
		"mov %0, %%rdx" : : "g"(params->arg2)
	);
two:
	__asm__ __volatile__(
		"mov %0, %%rsi" : : "g"(params->arg1)
	);
one:
	__asm__ __volatile__(
		"mov %0, %%rdi" : : "g"(params->arg0)
	);
zero:
	/* Call to real function should be here to insert in arguments*/
	/* What we have here is 1) Function address, 2) function arguments, but
	 * no function prototype...don't know how to call the function*/
	__asm__ __volatile__(
		"call %0" : : "g"(params->jump_addr)
	);
	free(args);
	return 0;
}

void mvx_start_hook(const char* caller_name)
{
	struct address_map* address;
	int pid;
	int status;
	void* stack_base = NULL;
	struct shim_arguments* args = malloc(sizeof(struct shim_arguments));
	pchild_stack = malloc(4096);
	stack_base = pchild_stack + 4096;
	//HASH_FIND_STR(address_hash, caller_name, address);

	/* Assemble arguments */
	args->jump_addr = cloned_function;
	args->num_args = 2;
	args->arg0 = 8080;
	args->arg1 = "Argument passed string \n";

	/* If we found the address, we want to clone thread using it*/
	//if (address)
		debug_printf("Address found is this: 0x%lx\n", address->variant_address);
		//pid = syscall(SYS_clone, (int (*) (void *))address->variant_address,
		//	    NULL, CLONE_NEWPID, NULL, NULL, NULL, NULL);

		pid = clone(__mvx_shim, stack_base, CLONE_VM, args);
		debug_printf("Clone has pid %d\n", pid);
		while(1) sleep(100);
		debug_printf("global_var = %d\n", global_var);
}

void mvx_end_hook(const char* caller_name)
{
	debug_printf("mvx_end_hook called\n");
}

int
wrpkru(unsigned int pkru)
{
    unsigned int eax = pkru;
    unsigned int ecx = 0;
    unsigned int edx = 0;
    asm volatile(".byte 0x0f,0x01,0xef\n\t"
                 : : "a" (eax), "c" (ecx), "d" (edx));
}

int
pkey_set(int pkey, unsigned long rights, unsigned long flags)
{
    unsigned int pkru = (rights << (2 * pkey));
    return wrpkru(pkru);
}

int
pkey_mprotect(void *ptr, size_t size, unsigned long orig_prot,
              unsigned long pkey)
{
    return syscall(SYS_pkey_mprotect, ptr, size, orig_prot, pkey);
}

int
pkey_alloc(void)
{
    return syscall(SYS_pkey_alloc, 0, 0);
}

int
pkey_free(unsigned long pkey)
{
    return syscall(SYS_pkey_free, pkey);
}

#define errExit(msg)    do { perror(msg); exit(EXIT_FAILURE); \
                           } while (0)

void __attribute__ ((constructor)) initLibrary(void)
{
	debug_printf("Lightweight mvx library instantiated last time\n");
	int status;
	int pkey;
	int *buffer;
	/*
	 *Allocate one page of memory
	 */
	buffer = mmap(NULL, getpagesize(), PROT_READ | PROT_WRITE,
	              MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (buffer == MAP_FAILED)
	    errExit("mmap");
	/*
	 * Put some random data into the page (still OK to touch)
	 */
	*buffer = __LINE__;
	printf("buffer contains: %d\n", *buffer);
	/*
	 * Allocate a protection key:
	 */
	pkey = pkey_alloc();
	if (pkey == -1)
	    errExit("pkey_alloc");
	/*
	 * Disable access to any memory with "pkey" set,
	 * even though there is none right now
	 */
	status = pkey_set(pkey, PKEY_DISABLE_ACCESS, 0);
	//if (status)
	//    printf("Status: %d\n", status);
	//    errExit("pkey_set");
	/*
	 * Set the protection key on "buffer".
	 * Note that it is still read/write as far as mprotect() is
	 * concerned and the previous pkey_set() overrides it.
	 */
	status = pkey_mprotect((void*)0x7ffff7fe4000, 2*getpagesize(),
	                       PROT_READ | PROT_WRITE | PROT_EXEC, pkey);
	status = pkey_mprotect((void*)0x7ffff7a3a000, 923*getpagesize(),
	                       PROT_READ | PROT_WRITE | PROT_EXEC, pkey);
	//status = pkey_mprotect(buffer, getpagesize(),
	//                       PROT_READ | PROT_WRITE | PROT_EXEC, pkey);
	//if (status == -1)
	//    errExit("pkey_mprotect");
	//printf("about to read buffer again...\n");
	/*
	 * This will crash, because we have disallowed access
	 */
	buffer[0] = 12345;
	printf("buffer contains: %d\n", *buffer);
	pkey_set(pkey,0,0);
	//struct address_map* entry = (struct address_map*) malloc(sizeof(struct
	//								address_map));
	//strcpy(entry->caller_name, "call_other_function");
	//entry->variant_address = (uint64_t)__mvx_shim;
	//HASH_ADD_STR(address_hash, caller_name, entry);
	/* mmap function lookup table */
	//mapping = mmap(NULL, sizeof(struct address_map)*LOOKUP_TABLE_SIZE,
	//		       PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
}

void __attribute__ ((destructor)) exitLibrary(void)
{
	debug_printf("Lightweight mvx library exited\n");
	free(pchild_stack);
	//munmap(mapping, sizeof(struct address_map)*LOOKUP_TABLE_SIZE);
}
