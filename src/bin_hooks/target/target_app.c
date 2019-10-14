#include <stdio.h>
#include <lightweight_mvx.h>

void call_other_function(char* string)
{
	mvx_start_hook(__func__);
	printf("This is the string: %s\n", string);
	mvx_end_hook(__func__);
}

void main ()
{
	call_other_function("Pass this string to function");
}
