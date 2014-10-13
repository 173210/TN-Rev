#include "lib.h"

void *memset(void *s, int c, size_t n)
{
	char *p = s;

	if (s != NULL)
		while(n) {
			*p = c;
			n--;
			p++;
		};

	return s;
};

void *memcpy(void *dest, const void *src, size_t n)
{
	char *p = dest;

	if (dest != NULL && src != NULL)
		while(n) {
			*p = *(char *)src;
			p++;
			src++;
			n--;
		};

	return dest;
};

void *FindImport(const void *p, const char *libname, int nid)
{
	SceLibraryStubTable *stub;
	const int umemEnd = 0x0A000000;
	int i;

	for (stub = p; (int)stub < umemEnd; stub = (void *)stub + 4) {
		if (stub->libname != libname
			&& stub->libname >= p && stub->libname < umemEnd
			&& stub->nidtable >= p && stub->nidtable < umemEnd
			&& stub->stubtable >= p && stub->stubtable < umemEnd
			&& !strcmp(libname, stub->libname))
			for (i = 0; i < stub->stubcount; i++)
				if (((int *)stub->nidtable)[i] == nid)
					return stub->stubtable + i * 8;
	}

	return NULL;
}

int strlen(const char * str) //sub_00010E94
{
	int c = 0;
	while(* str)
	{
		str++;
		c++;
	};
	
	return c;
};

int strcmp(const char *s1, const char *s2) //sub_00010F14
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
