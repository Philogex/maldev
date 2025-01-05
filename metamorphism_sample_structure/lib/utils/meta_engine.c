// This should be compiled to a pe and appended to the main executable. i don't need to modify headers, since i will load this pe manuall and the memory view doesn't need to reflect this
// This should also be added to the function_encrypter.cpp, since big antivirus doesn't like appended executables
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
    ULONGLONG virtualAddress;
    ULONGLONG physicalAddress;
    ULONGLONG size;
    char name[64];
} FunctionInfo;

typedef struct {
    char executablePath[512];
    size_t numFunctions;
    FunctionInfo *functions;
    unsigned char recryptionKey;
    unsigned char nextEncryptionKey;
    uintptr_t keyAddress;
} ProcessData;

// https://nachtimwald.com/2017/11/18/base64-encode-and-decode-in-c/
size_t b64_decoded_size(const char *in)
{
    size_t len;
    size_t ret;
    size_t i;

    if (in == NULL)
        return 0;

    len = strlen(in);
    ret = len / 4 * 3;

    for (i=len; i-->0; ) {
        if (in[i] == '=') {
            ret--;
        } else {
            break;
        }
    }

    return ret;
}

const int b64invs[] = { 
    62, -1, -1, -1, 63, 52, 53, 54, 55, 56, 57, 58,
    59, 60, 61, -1, -1, -1, -1, -1, -1, -1, 0, 1, 2, 3, 4, 5,
    6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
    21, 22, 23, 24, 25, -1, -1, -1, -1, -1, -1, 26, 27, 28,
    29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42,
    43, 44, 45, 46, 47, 48, 49, 50, 51 
};

int b64_isvalidchar(char c)
{
    if (c >= '0' && c <= '9')
        return 1;
    if (c >= 'A' && c <= 'Z')
        return 1;
    if (c >= 'a' && c <= 'z')
        return 1;
    if (c == '+' || c == '/' || c == '=')
        return 1;
    return 0;
}

int b64_decode(const char *in, unsigned char *out, size_t outlen)
{
    size_t len;
    size_t i;
    size_t j;
    int    v;

    if (in == NULL || out == NULL)
        return 0;

    len = strlen(in);
    if (outlen < b64_decoded_size(in) || len % 4 != 0)
        return 0;

    for (i=0; i<len; i++) {
        if (!b64_isvalidchar(in[i])) {
            return 0;
        }
    }

    for (i=0, j=0; i<len; i+=4, j+=3) {
        v = b64invs[in[i]-43];
        v = (v << 6) | b64invs[in[i+1]-43];
        v = in[i+2]=='=' ? v << 6 : (v << 6) | b64invs[in[i+2]-43];
        v = in[i+3]=='=' ? v << 6 : (v << 6) | b64invs[in[i+3]-43];

        out[j] = (v >> 16) & 0xFF;
        if (in[i+2] != '=')
            out[j+1] = (v >> 8) & 0xFF;
        if (in[i+3] != '=')
            out[j+2] = v & 0xFF;
    }

    return 1;
}

void readSharedMemory(char *argv1, ProcessData **processData) {
    // currently only deserializes the commandline params
    size_t decoded_len = b64_decoded_size(argv1)+1;
    char *buffer = malloc(decoded_len);

    b64_decode(argv1, (unsigned char *)buffer, decoded_len);

    unsigned char *ptr = (unsigned char *)buffer;

    size_t total_size = sizeof(((ProcessData*)0)->executablePath) +
                        sizeof(((ProcessData*)0)->numFunctions) + 
                        sizeof(((ProcessData*)0)->recryptionKey) +
                        sizeof(((ProcessData*)0)->nextEncryptionKey) +
                        sizeof(((ProcessData*)0)->keyAddress);

    // Add size of functions
    for(size_t i = 0; i < (size_t)*(buffer + sizeof(((ProcessData*)0)->executablePath)); ++i) {
        total_size += sizeof(((FunctionInfo*)0)->virtualAddress) + sizeof(((FunctionInfo*)0)->physicalAddress) + sizeof(((FunctionInfo*)0)->size) + sizeof(((FunctionInfo*)0)->name);
        printf("Current Size: 0x%04llX\n", total_size);
    }

    printf("Total Size: 0x%04llX\n", total_size);

    // Allocate memory for ProcessData
    ProcessData *data = (ProcessData *)malloc(total_size);
    if (!data) {
        fprintf(stderr, "Failed to allocate memory for ProcessData\n");
        free(buffer);
        return;
    }

    // Deserialize executablePath
    memcpy(data->executablePath, ptr, sizeof(data->executablePath));
    ptr += sizeof(data->executablePath);
    printf("Executable Path: %s\n", data->executablePath);

    // Deserialize numFunctions
    memcpy(&data->numFunctions, ptr, sizeof(data->numFunctions));
    ptr += sizeof(data->numFunctions);
    printf("Number of Functions: %zu\n", data->numFunctions);

    // Allocate memory for FunctionInfo array
    data->functions = (FunctionInfo *)malloc(data->numFunctions * (sizeof(ULONGLONG) + sizeof(ULONGLONG) + sizeof(ULONGLONG) + sizeof(((FunctionInfo*)0)->name)));
    if (!data->functions) {
        fprintf(stderr, "Failed to allocate memory for FunctionInfo array\n");
        free(buffer);
        free(data);
        return;
    }

    // Deserialize FunctionInfo array
    for (size_t i = 0; i < data->numFunctions; ++i) {
        memcpy(&(data->functions[i].virtualAddress), ptr, sizeof(ULONGLONG));
        ptr += sizeof(ULONGLONG);

        memcpy(&(data->functions[i].physicalAddress), ptr, sizeof(ULONGLONG));
        ptr += sizeof(ULONGLONG);

        memcpy(&(data->functions[i].size), ptr, sizeof(ULONGLONG));
        ptr += sizeof(ULONGLONG);

        memcpy(&(data->functions[i].name), ptr, sizeof(data->functions[i].name));
        ptr += sizeof(data->functions[i].name);
    }
    for (size_t i = 0; i < data->numFunctions; ++i) {
        printf("Function %zu:\tVA: 0x%08llX, PA: 0x%08llX, S: %08llu, N: %s\n", i, data->functions[i].virtualAddress, data->functions[i].physicalAddress, data->functions[i].size, data->functions[i].name);
    }

    // Deserialize recryptionKey
    memcpy(&data->recryptionKey, ptr, sizeof(data->recryptionKey));
    ptr += sizeof(data->recryptionKey);
    printf("Recryption Key: 0x%hhX\n", data->recryptionKey);

    // Deserialize nextEncryptionKey
    memcpy(&data->nextEncryptionKey, ptr, sizeof(data->nextEncryptionKey));
    ptr += sizeof(data->nextEncryptionKey);
    printf("Next Encryption Key: 0x%hhX\n", data->nextEncryptionKey);

    // Deserialize keyAddress
    memcpy(&data->keyAddress, ptr, sizeof(data->keyAddress));
    ptr += sizeof(data->keyAddress);
    printf("Key Address: 0x%08llu\n\n", data->keyAddress);

    free(buffer);
    *processData = data;
}

void encryptPhysicalFunctions(ProcessData *processData) {
    if(processData == NULL) {
        printf("Failed to read Shared Memory.");
        return;
    }

    // Use the data passed to the new process
    const char *executablePath = processData->executablePath;
    FunctionInfo *functions = processData->functions;
    size_t numFunctions = processData->numFunctions;
    unsigned char recryptionKey = processData->recryptionKey;
    unsigned char nextEncryptionKey = processData->nextEncryptionKey;
    UINT_PTR keyAddress = processData->keyAddress;

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
            fclose(file);
            return;
        }
        
        // Perform XOR encryption on the function's physical address
        xor(data, functionSize, recryptionKey);

        // Seek back to the specified offset for writing
        if (fseek(file, functionAddress, SEEK_SET) != 0) {
            fprintf(stderr, "Error seeking back to offset: %llu\n", functionAddress);
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

int main(int argc, char* argv[]) {
    printf("Nothing to see here :D\n");

    ProcessData *processData = NULL;
    readSharedMemory(argv[1], &processData);

    //WaitForSingleObject or something to wait for other process to terminate, or i inherit handles and close itself... idk
    Sleep(10000);

    encryptPhysicalFunctions(processData);
    free(processData);

    //get sharedProcessInformation
    return 0;
}