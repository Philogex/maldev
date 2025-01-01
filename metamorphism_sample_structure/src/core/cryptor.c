/*
func decrypt_control_flow
func encrypt_control_flow

func overwrite_disk_binary
*/

#include "cryptor.h"
#include "../crypto/xor.h"

void overwrite_offset(const char *file_path, long offset, const void *data, size_t data_size) {
    FILE *file = fopen(file_path, "r+b"); // Open file in read-write binary mode
    if (!file) {
        perror("Error opening file");
        exit(EXIT_FAILURE);
    }

    // Seek to the desired offset
    if (fseek(file, offset, SEEK_SET) != 0) {
        perror("Error seeking to offset");
        fclose(file);
        exit(EXIT_FAILURE);
    }

    // Write the data at the specified offset
    if (fwrite(data, 1, data_size, file) != data_size) {
        perror("Error writing data");
        fclose(file);
        exit(EXIT_FAILURE);
    }

    fclose(file);
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

FunctionInfo* analyzeExecutable(size_t *numFunctions) {
    UINT_PTR baseAddress = (UINT_PTR)GetModuleHandle(NULL);
    if (baseAddress == 0) {
        printf("Error: Unable to get module handle.\n");
        return NULL; // Exit with an error
    }
    printf("Base Address: 0x%llX\n", baseAddress);

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)baseAddress;
    PIMAGE_NT_HEADERS64 pNtHeaders = (PIMAGE_NT_HEADERS64)(baseAddress + pDosHeader->e_lfanew);
    PIMAGE_OPTIONAL_HEADER64 pOptionalHeader = (PIMAGE_OPTIONAL_HEADER64)(&pNtHeaders->OptionalHeader);

    printf("DOS Header starting at: 0x%p\n", pDosHeader);
    printf("NT Header starting at: 0x%p\n", pNtHeaders);
    printf("NT Optional Header starting at: 0x%p\n", pOptionalHeader);
    printf("NT Optional Header Image Base address at: 0x%llx\n", pOptionalHeader->ImageBase);

    PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((UINT_PTR)(&pNtHeaders->OptionalHeader) + pNtHeaders->FileHeader.SizeOfOptionalHeader);

    ULONGLONG metaSectionVA = 0;
    DWORD metaSectionSize = 0;

    for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        if (strncmp((char *)pSectionHeader[i].Name, ".meta", 5) == 0) {
            metaSectionVA = pSectionHeader[i].VirtualAddress;
            metaSectionSize = pSectionHeader[i].SizeOfRawData;
            break;
        }
    }

    if (metaSectionVA == 0) {
        printf("Error: .meta section not found.\n");
        return NULL;
    }

    printf(".meta Section Address: 0x%llX, Size: 0x%lX bytes\n", metaSectionVA, metaSectionSize);

    // MISSING (Parse Metadata from Header)
    FunctionInfo *functions = NULL;

    // Deserialize the function data
    deserializeFunctionData(baseAddress + metaSectionVA, &functions, numFunctions);

    // Print the deserialized data
    for (size_t i = 0; i < *numFunctions; i++) {
        printf("Function %zu:\n", i + 1);
        printf("Virtual Address: 0x%llx\n", functions[i].virtualAddress);
        printf("Physical Address: 0x%llx\n", functions[i].physicalAddress);
        printf("Size: 0x%llx\n", functions[i].size);
        printf("Name: %s\n\n", functions[i].name);
    }

    // Return the list of functions (if we were to fill functionList here)
    // Note: The function list is currently not fully implemented here
    return functions;  // Function list would be returned here once populated
}

void decrypt_functions() {
    FunctionInfo* functions = NULL;
    size_t numFunctions = 0;

    // Analyze the executable to retrieve the function information
    functions = analyzeExecutable(&numFunctions);
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

    // Encryption key (should match the key used during encryption)
    unsigned char encryptionKey = 0xAA;

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

void encrypt_functions() {
	UINT_PTR baseAddress = (UINT_PTR)GetModuleHandle(NULL);
    FunctionInfo* functions = NULL;
    size_t numFunctions = 0;
	functions = analyzeExecutable(&numFunctions);


}