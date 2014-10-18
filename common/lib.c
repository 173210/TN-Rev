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

int _strcmp(const char *s1, const char *s2) //sub_00010F14
{
	int val = 0;
	const unsigned char *u1, *u2;

	u1 = (unsigned char *) s1;
	u2 = (unsigned char *) s2;

	while(1)
	{
		if(*u1 != *u2)
		{
			val = (int) *u1 - (int) *u2;
			break;
		}

		if((*u1 == 0) && (*u2 == 0))
		{
			break;
		}

		u1++;
		u2++;
	}

	return val;
}