/*
func decrypt_control_flow
func encrypt_control_flow

func overwrite_disk_binary
*/

#include "cryptor.h"
#include "../crypto/xor.h"

DWORD Rva2Offset(DWORD dwRva, UINT_PTR uiBaseAddress)
{
    WORD wIndex = 0;
    PIMAGE_SECTION_HEADER pSectionHeader = NULL;
    PIMAGE_NT_HEADERS pNtHeaders = NULL;

    pNtHeaders = (PIMAGE_NT_HEADERS)(uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew);
    pSectionHeader = (PIMAGE_SECTION_HEADER)((UINT_PTR)(&pNtHeaders->OptionalHeader) + pNtHeaders->FileHeader.SizeOfOptionalHeader);

    if (dwRva < pSectionHeader[0].PointerToRawData)
        return dwRva;

    for (wIndex = 0; wIndex < pNtHeaders->FileHeader.NumberOfSections; wIndex++)
    {
        if (dwRva >= pSectionHeader[wIndex].VirtualAddress && dwRva < (pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].SizeOfRawData))
            return (dwRva - pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].PointerToRawData);
    }

    return 0;
}

void printSectionHeaders() {
    HMODULE hModule = GetModuleHandle(NULL); // Get base address of current executable
    if (!hModule) {
        printf("Error: Unable to get module handle.\n");
        return;
    }

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE *)hModule + dosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)((BYTE *)&ntHeaders->OptionalHeader + ntHeaders->FileHeader.SizeOfOptionalHeader);

    printf("Section headers:\n");
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i) {
        printf("Name: %.8s\n", sectionHeader[i].Name);
        printf("Virtual Address: 0x%lX\n", sectionHeader[i].VirtualAddress);
        printf("Size of Raw Data: 0x%lX\n", sectionHeader[i].SizeOfRawData);
        printf("Pointer to Raw Data: 0x%lX\n\n", sectionHeader[i].PointerToRawData);
    }
}

void deserializeFunctionData(ULONGLONG startOffset, FunctionInfo **functions, size_t *numFunctions) {
    // Read the size of the array (8 bytes)
    ULONGLONG arraySize = 0;
    memcpy(&arraySize, (void*)startOffset, sizeof(ULONGLONG));

    *numFunctions = (size_t)arraySize;  // Set the number of functions

    // Allocate memory for the functions array
    *functions = (FunctionInfo *)malloc(sizeof(FunctionInfo) * (*numFunctions));
    if (*functions == NULL) {
        perror("Failed to allocate memory for functions");
        return;
    }

    // Read each FunctionInfo struct
    for (size_t i = 0; i < *numFunctions; i++) {
        memcpy(&(*functions)[i], (void*)(startOffset + sizeof(ULONGLONG) + i * sizeof(FunctionInfo)), sizeof(FunctionInfo));
    }
}

// all of these getters should be combined to just return a struct of information about any section...
DWORD getMetaSectionPhysicalSize(UINT_PTR baseAddress) {
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)baseAddress;
    PIMAGE_NT_HEADERS64 pNtHeaders = (PIMAGE_NT_HEADERS64)(baseAddress + pDosHeader->e_lfanew);
    PIMAGE_OPTIONAL_HEADER64 pOptionalHeader = (PIMAGE_OPTIONAL_HEADER64)(&pNtHeaders->OptionalHeader);
    PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((UINT_PTR)(&pNtHeaders->OptionalHeader) + pNtHeaders->FileHeader.SizeOfOptionalHeader);

    for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        if (strncmp((char *)pSectionHeader[i].Name, ".meta", 5) == 0) {
            return pSectionHeader[i].SizeOfRawData;
        }
    }
    return 0; // Return 0 if .meta section is not found
}

DWORD getMetaSectionVirtualSize(UINT_PTR baseAddress) {
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)baseAddress;
    PIMAGE_NT_HEADERS64 pNtHeaders = (PIMAGE_NT_HEADERS64)(baseAddress + pDosHeader->e_lfanew);
    PIMAGE_OPTIONAL_HEADER64 pOptionalHeader = (PIMAGE_OPTIONAL_HEADER64)(&pNtHeaders->OptionalHeader);
    PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((UINT_PTR)(&pNtHeaders->OptionalHeader) + pNtHeaders->FileHeader.SizeOfOptionalHeader);

    for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        if (strncmp((char *)pSectionHeader[i].Name, ".meta", 5) == 0) {
            return pSectionHeader[i].Misc.VirtualSize;
        }
    }
    return 0; // Return 0 if .meta section is not found
}

// Function to get the virtual address of the .meta section
ULONGLONG getMetaSectionAddress(UINT_PTR baseAddress) {
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)baseAddress;
    PIMAGE_NT_HEADERS64 pNtHeaders = (PIMAGE_NT_HEADERS64)(baseAddress + pDosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((UINT_PTR)(&pNtHeaders->OptionalHeader) + pNtHeaders->FileHeader.SizeOfOptionalHeader);

    for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        if (strncmp((char *)pSectionHeader[i].Name, ".meta", 5) == 0) {
            return pSectionHeader[i].VirtualAddress;
        }
    }
    return 0; // Return 0 if .meta section is not found
}

FunctionInfo* analyzeExecutable(size_t *numFunctions) {
    UINT_PTR baseAddress = (UINT_PTR)GetModuleHandle(NULL);
    if (baseAddress == 0) {
        printf("Error: Unable to get module handle.\n");
        return NULL; // Exit with an error
    }
    printf("Base Address: 0x%llX\n", baseAddress);

    // Get the size and address of the .meta section
    DWORD metaSectionSize = getMetaSectionVirtualSize(baseAddress);
    if (metaSectionSize == 0) {
        printf("Error: Unable to retrieve size of .meta section.\n");
        return NULL;
    }

    ULONGLONG metaSectionVA = getMetaSectionAddress(baseAddress);
    if (metaSectionVA == 0) {
        printf("Error: Unable to retrieve address of .meta section.\n");
        return NULL;
    }

    printf(".meta Section Address: 0x%llX, Size: 0x%lX bytes\n", metaSectionVA, metaSectionSize);

    // Deserialize the function data
    FunctionInfo *functions = NULL;
    deserializeFunctionData(baseAddress + metaSectionVA, &functions, numFunctions);

    // Print the deserialized data
    for (size_t i = 0; i < *numFunctions; i++) {
        printf("Function %zu:\n", i + 1);
        printf("Virtual Address: 0x%llx\n", functions[i].virtualAddress);
        printf("Physical Address: 0x%llx\n", functions[i].physicalAddress);
        printf("Size: 0x%llx\n", functions[i].size);
        printf("Name: %s\n\n", functions[i].name);
    }

    return functions;
}

void decrypt_functions() { //this should have a string or index parameter soon, so they can get dynamically de- and encrypted
    FunctionInfo* functions = NULL;
    size_t numFunctions = 0;

    // Analyze the executable to retrieve the function information
    functions = analyzeExecutable(&numFunctions);
    printf("Analyzed Executable.\n");
    if (functions == NULL || numFunctions == 0) {
        fprintf(stderr, "No functions found or failed to analyze executable.\n");
        return;
    }

    // Get the base address of the loaded module
    UINT_PTR baseAddress = (UINT_PTR)GetModuleHandle(NULL);
    if (baseAddress == 0) {
        fprintf(stderr, "Failed to get the base address of the module.\n");
        return;
    }

    // Dynamically parse encryptionKey
    unsigned char encryptionKey = 0x00;
    encryptionKey = *((unsigned char *)(baseAddress + getMetaSectionAddress(baseAddress) + getMetaSectionVirtualSize(baseAddress) - sizeof(encryptionKey)));
    
    if(encryptionKey == 0x00) {
        printf("Encryption Key not found.\n");
        exit(0);
    }

    printf("Key Address: 0x%llX\n", baseAddress + getMetaSectionAddress(baseAddress) + getMetaSectionVirtualSize(baseAddress) - sizeof(encryptionKey));
    printf("Encryption Key: 0x%hhX\n", encryptionKey);

    // Loop through all functions and decrypt them in memory
    for (size_t i = 0; i < numFunctions; ++i) {
        FunctionInfo* function = &functions[i];

        // Calculate the absolute memory address of the function
        UINT_PTR functionAddress = baseAddress + function->virtualAddress;

        // Check if the function size is valid
        if (function->size == 0) {
            fprintf(stderr, "Function %s has size 0. Skipping.\n", function->name);
            continue;
        }

        DWORD oldProtect;
        if (!VirtualProtect((LPVOID)functionAddress, function->size, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            fprintf(stderr, "Failed to change memory protection for function: %s at address: 0x%p.\n",
                    function->name, (void*)functionAddress);
            continue;
        }
        
        // Perform XOR decryption on the function's memory
        unsigned char* functionMemory = (unsigned char*)functionAddress;
        xor(functionMemory, function->size, encryptionKey);

        // Restore the original memory protection
        if (!VirtualProtect((LPVOID)functionAddress, function->size, oldProtect, &oldProtect)) {
            fprintf(stderr, "Failed to restore memory protection for function: %s at address: 0x%p.\n",
                    function->name, (void*)functionAddress);
        }

        // Log the operation for debugging purposes
        printf("Decrypted function: %s at address: 0x%p with size: %llu bytes.\n",
               function->name,
               (void*)functionAddress,
               function->size);
    }

    free(functions);

    printf("All functions decrypted successfully!\n");
}