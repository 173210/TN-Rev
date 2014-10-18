#include "lib.h"

void *memset(void *s, int c, size_t n)
{
	char *p = s;

	if (p != NULL)
		while(n) {
			*p = c;
			n--;
			p++;
		};

	return s;
}

void *memcpy(void *dest, const void *src, size_t n)
{
	char *p = dest;

	if (dest == NULL || src == NULL)
		return NULL;

	while(n) {
		*p = *(char *)src;
		n--;
		p++;
		src++;
	};

	return dest;
};

int strcmp(const char *s1, const char *s2)
{
	const unsigned char *u1 = (unsigned char *)s1;
	const unsigned char *u2 = (unsigned char *)s2;

	if (s1 != NULL && s2 != NULL)
		while(*u1) {
			if(*u1 != *u2)
				return *u1 - *u2;

			u1++;
			u2++;
		}

	return 0;
}
