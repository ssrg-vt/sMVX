#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>

/* Local headers */
#include <debug.h>
#include <config.h>
#include <address_map.h>

#define LOOKUP_TABLE_SIZE	(100)
struct address_map* mapping;

void run_lightweight_mvx()
{
	int fd;
	char string[100];
	int strlen = sprintf(string, "Return address is: %lx\n",
		__builtin_return_address(0));
	fd = open("testfile.txt", O_RDWR | O_CREAT);
	if (fd < 0)
		return;

	write(fd, string, strlen);
}

void __attribute__ ((constructor)) initLibrary(void)
{
	debug_printf("Lightweight mvx library instantiated\n");

	/* mmap function lookup table */
	mapping = mmap(NULL, sizeof(struct address_map)*LOOKUP_TABLE_SIZE,
		       PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
}

void __attribute__ ((destructor)) exitLibrary(void)
{
	debug_printf("Lightweight mvx library exited\n");
	munmap(mapping, sizeof(struct address_map)*LOOKUP_TABLE_SIZE);
}
