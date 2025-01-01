#ifndef CRYPTOR_H
#define CRYPTOR_H

#include <windows.h>
#include <imagehlp.h>
#include <winnt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../data/config.h"

typedef struct {
	ULONGLONG virtualAddress; // RVA offset
    ULONGLONG physicalAddress; // File offset
    ULONGLONG size;            // Size of the function
    char name[64];        // Name of the function
} FunctionInfo;

extern void decrypt_function(const unsigned char *encrypted, size_t size);
extern void printSectionHeaders();
extern FunctionInfo* analyzeExecutable();

#endif // CRYPTOR_H