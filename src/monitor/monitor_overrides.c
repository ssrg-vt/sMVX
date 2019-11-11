#include <monitor_trampoline.h>
#include <pkey.h>

//extern unsigned long pkey;

/* Real functions not being overridden */
int (*real_printf)(const char* restrict fmt, ...);

/* Functions we are overriding */
int printf(const char *restrict fmt, ...)
{
	deactivate_pkey();
	real_printf("Intercepted printf!, Actual string: %s\n", fmt);
	//activate_pkey();
	return 1;
}
