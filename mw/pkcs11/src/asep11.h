/*
 * asep11.h
 *
 *  Created on: Dec 18, 2013
 *      Author: Juan Marcelo Barrancos Clavijo
 */

#ifndef ASEP11_H_
#define ASEP11_H_

#ifndef NULL
#ifdef __cplusplus
#define NULL    0
#else
#define NULL    ((void *) 0)
#endif
#endif

#define CLEANUP(a)   { ret = (a); goto cleanup; }

#include <stdio.h>
#ifdef WIN32

#include <windows.h>
#include <conio.h>
#include <tchar.h>
#include <strsafe.h>

#include "include/rsaref220/win32.h"
#pragma pack(push, cryptoki, 1)
#include "include/rsaref220/pkcs11.h"
#pragma pack(pop, cryptoki)


#define dlopen(lib,h) LoadLibrary(lib)
#define dlsym(h, function) GetProcAddress(h, function)
#define dlclose(h) FreeLibrary(h)
#ifdef _DEBUG
  #define PKCS11_LIB TEXT("beidpkcs11D.dll")
#else
  #define PKCS11_LIB TEXT("beidpkcs11.dll")
#endif

#define RTLD_LAZY	1
#define RTLD_NOW	2
#define RTLD_GLOBAL 4

#define ASEP11_LIB TEXT("asepkcs.dll")

#else
#include <dlfcn.h>
#include <unistd.h>
#include <string.h>

#include "include/rsaref220/unix.h"
#include "include/rsaref220/pkcs11.h"

#ifdef __APPLE__
#define ASEP11_LIB "/usr/local/lib/libASEP11.so"
#else
#define ASEP11_LIB "/usr/local/lib/libASEP11.so"
#endif
#define TEXT(x) x
#define _getch() getchar()

#endif

#include <stdlib.h>


CK_FUNCTION_LIST_PTR pFunctions;        //list of the pkcs11 function pointers
CK_C_GetFunctionList pC_GetFunctionList;



#endif /* ASEP11_H_ */
