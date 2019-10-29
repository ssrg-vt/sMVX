#include <stdio.h>
#include <unistd.h>
#include <lightweight_mvx.h>

void call_other_function(char* string)
{
	test_function();
	printf("This is the string: %s\n", string);
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
