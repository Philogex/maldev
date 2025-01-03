#ifndef LOADER_H
#define LOADER_H

#include <windows.h>
#include <imagehlp.h>
#include <winnt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <direct.h>
#include <time.h>
#include "../data/config.h"
#include "../core/cryptor.h"

typedef struct {
    const char *executablePath;
    FunctionInfo *functions;
    size_t numFunctions;
    unsigned char recryptionKey;
    unsigned char nextEncryptionKey;
    UINT_PTR keyAddress;
} ProcessData;

#endif // LOADER_H