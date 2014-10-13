#ifndef LIB_H
#define LIB_H

#include <pspdisplay.h>
#include <pspctrl.h>
#include <pspkernel.h>
#include <pspge.h>
#include <pspdebug.h>
#include <pspaudio.h>
#include <psputility.h>
#include <pspumd.h>
#include <psptypes.h>
#include <pspimpose_driver.h>
#include <psputility.h>
#include <psploadexec_kernel.h>

void *memset(void *s, int c, size_t n);
void *memcpy(void *dest, const void *src, size_t n);
int ValidUserAddress(void * addr);
void *FindImport(const void *p, const char *libname, int nid);
unsigned FindFunction(const char * modulename, const char * library, unsigned nid);

#endif