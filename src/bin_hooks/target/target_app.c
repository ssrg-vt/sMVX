#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sched.h>
//#include <lightweight_mvx.h>
#include <monitor_trampoline.h>

int cloned_function(void* p)
{
	unsigned long pid = getpid();
	printf("Cloned function userspace calling from pid: %lu \n", pid);
	return 0;
}

void call_other_function(char* string)
{
	int pid = 0;
	char* stack;
	char* stackTop;

	printf("This is the string: %s\n", string);
	ld_preload_function(pid);
	/* Fork Test */
	//pid = fork();
	//if (!pid)
	//	printf("Userspace says this fork succeeded, we are the child process, pid is %d \n", pid);
	//else
	//	printf("Userspace says this fork succeeded, we are the parent process!m pid is %d\n", pid);

	/* Clone Test */
	stack = malloc(4096);
	stackTop = stack + 4096;
	pid = clone(cloned_function, stackTop, CLONE_FILES | SIGCHLD, NULL);

	//a = (char*)malloc(16);
	// Redirect stderr to stdout
	//dup2(1, 2);
	//printf("step 3: stderr redirected to stdout\n");

	//// Duplicate stderr to arbitrary fd
	//dup2(2, 42);
	//printf("step 4: !! YOU SHOULD NOT SEE ME !!\n");
}

void main ()
{
	call_other_function("Pass this string to function");
}
