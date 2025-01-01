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
    ULONGLONG physicalAddress; // File offset
    ULONGLONG size;            // Size of the function
    char name[256];        // Name of the function
} FunctionInfo;

extern void decrypt_function(const unsigned char *encrypted, size_t size);
extern void printSectionHeaders();
extern FunctionInfo* analyzeExecutable(size_t* functionCount);

#endif // CRYPTOR_H