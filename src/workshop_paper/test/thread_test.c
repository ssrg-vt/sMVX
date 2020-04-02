#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>

#include "../lib/libthreadtest.h"

char cmd[128];

void *thread_func(void* nothing)
{
	library_func();
	return NULL;
}

int main()
{
	pthread_t thread1, thread2;

	int  iret1, iret2;
	/* Create independent threads each of which will execute function */
	iret1 = pthread_create( &thread1, NULL, thread_func, NULL);
	iret2 = pthread_create( &thread2, NULL, thread_func, NULL);

	/* Wait till threads are complete before main continues. Unless we  */
	/* wait we run the risk of executing an exit which will terminate   */
	/* the process and all threads before the threads have completed.   */
	pthread_join( thread1, NULL);
	pthread_join( thread2, NULL);
	printf("Thread 1 returns: %d\n",iret1);
	printf("Thread 2 returns: %d\n",iret2);

	while(1) usleep(5000);

	return 0;
}
