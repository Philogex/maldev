/*
func decrypt_control_flow
func encrypt_control_flow

func overwrite_disk_binary
*/

#include "cryptor.h"
#include "../crypto/xor.h"


void writeToDisk(const ThreadData* threadInfo);

//too much telemetry if i keep opening the filestream
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

DWORD WINAPI thread_func(LPVOID lpParam) {
    const ThreadData *ThreadInfo = (const ThreadData *)lpParam;

    printf("Secondary thread started...\n");  // This should appear if the thread is running

    writeToDisk(ThreadInfo);

    printf("Secondary thread finished...\n");  // This should appear when the thread finishes
    return 0;
}

void encrypt_physical_functions() {
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

    // Generate next decryption key
    srand(time(NULL));
    unsigned char nextEncryptionKey = (unsigned char)(rand() % 256);
    printf("Next Encryption Key: 0x%hhX\n", nextEncryptionKey);

    // Encryption key (should match the key used during encryption)
    unsigned char encryptionKey = 0x00;
    encryptionKey = *((unsigned char *)(baseAddress + getMetaSectionAddress(baseAddress) + getMetaSectionVirtualSize(baseAddress) - sizeof(encryptionKey)));
    if(encryptionKey == 0x00) {
        printf("Encryption Key not found.\n");
        exit(0);
    }

    unsigned char recryptionKey = nextEncryptionKey ^ encryptionKey;

    // Get the current executable path
    char executablePath[512];
    if (GetModuleFileName(NULL, executablePath, sizeof(executablePath)) == 0) {
        fprintf(stderr, "Error getting executable path: %ld\n", GetLastError());
        return;
    }
    
    printf("Current executable path: %s\n", executablePath);

    UINT_PTR keyAddress = Rva2Offset((UINT_PTR)getMetaSectionAddress(baseAddress), baseAddress);

    // Create a structure to pass the data to the thread
    ThreadData *threadData = (ThreadData *)malloc(sizeof(ThreadData));
    if (threadData == NULL) {
        fprintf(stderr, "Error allocating memory for thread data\n");
        return;
    }

    threadData->executablePath = executablePath;
    threadData->functions = functions;
    threadData->numFunctions = numFunctions;
    threadData->recryptionKey = recryptionKey;
    threadData->nextEncryptionKey = nextEncryptionKey;
    threadData->keyAddress = keyAddress;

    // Create a secondary thread to handle the file modification after termination
    HANDLE hThread = CreateThread(NULL, 0, thread_func, (LPVOID)threadData, 0, NULL);
    if (hThread == NULL) {
        fprintf(stderr, "Error creating thread: %ld\n", GetLastError());
        free(threadData);  // Don't forget to free memory on error
        return;
    } else {
        printf("Thread created successfully!\n");
    }

    // Now that the thread is created, we can safely terminate the main process
    //printf("Main process terminating...\n");
    //ExitProcess(0);  // Terminate the current process to release the file lock
}

void writeToDisk(const ThreadData* threadInfo) {
    printf("Started secondary thread and waiting 2 secs...\n");

    Sleep(2000);

    printf("Starting modification...\n");

    // Cast the argument back to the correct structure
    ThreadData *data = (ThreadData *)threadInfo;

    // Use the data passed to the thread
    const char *executablePath = data->executablePath;
    FunctionInfo *functions = data->functions;
    size_t numFunctions = data->numFunctions;
    unsigned char recryptionKey = data->recryptionKey;
    unsigned char nextEncryptionKey = data->nextEncryptionKey;
    UINT_PTR keyAddress = data->keyAddress;

    // Clean up the memory used by the structure
    free(data);  // Don't forget to free the allocated memory

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