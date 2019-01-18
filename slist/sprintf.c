#include <stdio.h>
#include <string.h>
#include <stdarg.h>

/* Allocate the required string and format it */ 
int msprintf(char** string, const char * format, ...)
{
	char dummy[2];
	char * result;
	size_t size;
	va_list ap;
	va_start(ap, format);
	/* SUS2 doesn't take size = 0, so we use 1. */ 
	size = vsnprintf(dummy, 1, format, ap);
	va_end(ap);
	result = checked_malloc(size);
	va_start(ap, format);
	size = vsnprintf(result, size, format, ap);
	va_end(ap);
	(*string) = result;
	return size;
}
