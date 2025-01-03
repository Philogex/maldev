// This should be compiled to a pe and appended to the main executable. i don't need to modify headers, since i will load this pe manuall and the memory view doesn't need to reflect this
#include <windows.h>
#include <imagehlp.h>
#include <winnt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <direct.h>
#include <time.h>
#include "../../src/crypto/xor.h"

#define SHARED_MEMORY_NAME "Meta\\ProcessInfo"

typedef struct {
    ULONGLONG virtualAddress; // RVA offset
    ULONGLONG physicalAddress; // File offset
    ULONGLONG size; // Size of the function in memory (it might error on disk... i'll take my chances for now)
    char name[64];        // Name of the function
} FunctionInfo;

typedef struct {
    const char *executablePath;
    FunctionInfo *functions;
    size_t numFunctions;
    unsigned char recryptionKey;
    unsigned char nextEncryptionKey;
    UINT_PTR keyAddress;
} ProcessData;

ProcessData *readSharedMemory() {
    // Create a structure to pass the data to the thread
    ProcessData *processData = (ProcessData *)malloc(sizeof(ProcessData)); //isn't this incorrect, since we don't know how large FunctionInfo * is?
    if (processData == NULL) {
        fprintf(stderr, "Error allocating memory for thread data\n");
        return NULL;
    }

    /*
    threadData->executablePath = executablePath;
    threadData->functions = functions;
    threadData->numFunctions = numFunctions;
    threadData->recryptionKey = recryptionKey;
    threadData->nextEncryptionKey = nextEncryptionKey;
    threadData->keyAddress = keyAddress;
    */

    return NULL;
}

void encrypt_physical_functions() {
    // Get ProcessInfo from other shared memory
    ProcessData *data = NULL;

    data = readSharedMemory();
    if(data == NULL) {
        printf("Failed to read Shared Memory.");
        free(data);
        return;
    }

    // Use the data passed to the new process
    const char *executablePath = data->executablePath;
    FunctionInfo *functions = data->functions;
    size_t numFunctions = data->numFunctions;
    unsigned char recryptionKey = data->recryptionKey;
    unsigned char nextEncryptionKey = data->nextEncryptionKey;
    UINT_PTR keyAddress = data->keyAddress;

    // Clean up the memory used by the structure
    free(data);

    //write exit command and wait for other process to terminate

    FILE *file = fopen(executablePath, "r+b");
    if (file == NULL) {
        fprintf(stderr, "Error opening file: %s\n", executablePath);
        return;
    }

    // Loop through all functions and reincrypt them for the next key
    for (size_t i = 0; i < numFunctions; ++i) {
        FunctionInfo* function = &functions[i];

        // Calculate the absolute memory address of the function
        UINT_PTR functionAddress = function->physicalAddress;

        // Check if the function size is valid
        ULONGLONG functionSize = function->size;
        if (functionSize == 0) {
            fprintf(stderr, "Function %s has size 0. Skipping.\n", function->name);
            continue;
        }

        // Allocate buffer for the data to be XORed
        unsigned char *data = (unsigned char *)malloc(functionSize);
        if (data == NULL) {
            fprintf(stderr, "Memory allocation error\n");
            fclose(file);
            return;
        }

        // Seek to the specified offset in the file
        if (fseek(file, functionAddress, SEEK_SET) != 0) {
            fprintf(stderr, "Error seeking to offset: %llu\n", functionAddress);
            fclose(file);
            return;
        }

        // Read the data from the file at the offset
        size_t bytesRead = fread(data, 1, functionSize, file);
        if (bytesRead != functionSize) {
            fprintf(stderr, "Error reading file data\n");
            free(data);
            fclose(file);
            return;
        }
        
        // Perform XOR encryption on the function's physical address
        xor(data, functionSize, recryptionKey);

        // Seek back to the specified offset for writing
        if (fseek(file, functionAddress, SEEK_SET) != 0) {
            fprintf(stderr, "Error seeking back to offset: %llu\n", functionAddress);
            free(data);
            fclose(file);
            return;
        }

        // Write the modified data back to the file
        size_t bytesWritten = fwrite(data, 1, functionSize, file);
        if (bytesWritten != functionSize) {
            fprintf(stderr, "Error writing modified data to file\n");
        }
        
        // Log the operation for debugging purposes
        printf("Recrypting function: %s at address: 0x%p with size: %llu bytes.\n",
               function->name,
               (void*)functionAddress,
               functionSize);

        free(data);
    }

    //Rewrite Key
    if (fseek(file, keyAddress, SEEK_SET) != 0) {
        fprintf(stderr, "Error seeking to offset: %llu\n", keyAddress);
        fclose(file);
        return;
    }

    // Write the modified data back to the file
    size_t bytesWritten = fwrite(&nextEncryptionKey, 1, sizeof(nextEncryptionKey), file);
    if (bytesWritten != sizeof(nextEncryptionKey)) {
        fprintf(stderr, "Error writing modified data to file\n");
    }

    // Cleanup
    fclose(file);
}

int main() {
    printf("Doing nothing :D\n");

    return 0;
}