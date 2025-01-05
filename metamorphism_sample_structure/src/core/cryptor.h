#ifndef CRYPTOR_H
#define CRYPTOR_H

#include <windows.h>
#include <imagehlp.h>
#include <winnt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <direct.h>
#include <time.h>
#include "../data/config.h"

typedef struct {
	ULONGLONG virtualAddress; // RVA offset
    ULONGLONG physicalAddress; // File offset
    ULONGLONG size; // Size of the function in memory (it might error on disk... i'll take my chances for now)
    char name[64];        // Name of the function
} FunctionInfo;

extern void decrypt_functions();
extern void printSectionHeaders();
extern ULONGLONG getMetaSectionAddress(UINT_PTR baseAddress);
extern DWORD getMetaSectionPhysicalSize(UINT_PTR baseAddress);
extern DWORD getMetaSectionVirtualSize(UINT_PTR baseAddress);
extern DWORD Rva2Offset(DWORD dwRva, UINT_PTR uiBaseAddress);
extern FunctionInfo* analyzeExecutable(size_t *numFunctions);

#endif // CRYPTOR_H