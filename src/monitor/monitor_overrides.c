#include <monitor_trampoline.h>
#include <pkey.h>

/* Real functions not being overridden */
int (*real_printf)(const char* restrict fmt, ...);

/* Functions we are overriding */
int printf(const char *restrict fmt, ...)
{
	DEACTIVATE();
	real_printf("Intercepted printf!, Actual string: %s\n", fmt);
	ACTIVATE();
	return 1;
}
