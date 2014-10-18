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

char * _strchr(char * str, char c)
{
	while(* str)
	{
		if(* str == c)
			return str;
			
		str++;
	};
	
	return NULL;
};

int ValidUserAddress(void * addr)
{
	if((u32)addr >= 0x08800000 && (u32)addr < 0x0A000000) 
		return 1;
		
	return 0;
}

u32 FindTextAddrByName(const char *modulename)
{
	u32 kaddr;
	for (kaddr = 0x88000000; kaddr < 0x88400000; kaddr += 4) {
		if (_strcmp((const char *)kaddr, modulename) == 0) {
			if ((*(u32*)(kaddr + 0x64) == *(u32*)(kaddr + 0x78)) && \
				(*(u32*)(kaddr + 0x68) == *(u32*)(kaddr + 0x88))) {
				if (*(u32*)(kaddr + 0x64) && *(u32*)(kaddr + 0x68))
					return *(u32*)(kaddr + 0x64);
			}
		}
	}
	return 0;
}

void * FindExport(const char *modulename, const char *library, u32 nid)
{
	u32 addr = FindTextAddrByName(modulename);

	if (addr) {
		for (; addr < 0x88400000; addr += 4) {
			if (_strcmp(library, (const char *)addr) == 0) {
				u32 libaddr = addr;

				while (*(u32*)addr != libaddr)
					addr -= 4;

				u8 variables = *(u8*)(addr + 9);
				u16 exports = (u16)(*(u16*)(addr + 10) + (u16)variables);
				u32 jump = (u32)exports * 4;

				addr = *(u32*)(addr + 12);

				while (exports--) {
					if (*(u32*)addr == nid)
						return (void *)(*(u32*)(addr + jump));

					addr += 4;
				}
				
				return 0;
			}
		}
	}

	return 0;
}