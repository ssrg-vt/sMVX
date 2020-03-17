#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define NUM_ITERATIONS (100000)

/* Calls getpid() in a loop */

int main()
{
	int i = 0;
	for (i = 0; i < NUM_ITERATIONS ; ++i) {
		getpid();
	}

	return 0;
}
