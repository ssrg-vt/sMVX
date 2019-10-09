#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

void run_lightweight_mvx()
{
	int fd;
	char* string = "Lightweight mvx called\n";
	int length = strlen(string);
	fd = open("testfile.txt", O_RDWR | O_CREAT);
	printf("run_lightweight_mvx called\n");
	if (fd < 0)
		return;

	write(fd, string, length);
}

void __attribute__ ((constructor)) initLibrary(void)
{
	printf("Lightweight mvx library instantiated\n");
}

void __attribute__ ((destructor)) exitLibrary(void)
{
	printf("Lightweight mvx library exited\n");
}
