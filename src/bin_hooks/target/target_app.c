#include <stdio.h>

void call_other_function(char* string)
{
	printf("This is the string: %s\n", string);
}

void main ()
{
	call_other_function("Pass this string to function");
}
