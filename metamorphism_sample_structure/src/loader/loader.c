#include "loader.h"

/*
NTSYSAPI 
NTSTATUS
NTAPI


NtUnmapViewOfSection(



  IN HANDLE               ProcessHandle,
  IN PVOID                BaseAddress );

*/

void GetPEFileSize(const char* peFilePath) {
    // Open the PE file
    FILE* file = fopen(peFilePath, "rb");
    if (!file) {
        fprintf(stderr, "Failed to open file\n");
        return;
    }

    // Read the DOS Header
    IMAGE_DOS_HEADER dosHeader;
    if (fread(&dosHeader, sizeof(IMAGE_DOS_HEADER), 1, file) != 1) {
        fprintf(stderr, "Failed to read DOS header\n");
        fclose(file);
        return;
    }

    // Check for the 'MZ' signature
    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        fprintf(stderr, "Invalid PE file (not a valid DOS header)\n");
        fclose(file);
        return;
    }

    // Move to the NT Header
    if (fseek(file, dosHeader.e_lfanew, SEEK_SET) != 0) {
        fprintf(stderr, "Failed to seek to NT header\n");
        fclose(file);
        return;
    }

    // Read the NT Header
    IMAGE_NT_HEADERS ntHeaders;
    if (fread(&ntHeaders, sizeof(IMAGE_NT_HEADERS), 1, file) != 1) {
        fprintf(stderr, "Failed to read NT header\n");
        fclose(file);
        return;
    }

    // Check for the 'PE\0\0' signature
    if (ntHeaders.Signature != IMAGE_NT_SIGNATURE) {
        fprintf(stderr, "Invalid PE file (not a valid NT header)\n");
        fclose(file);
        return;
    }

    // Calculate the PE file size
    DWORD fileSize = ntHeaders.OptionalHeader.SizeOfHeaders;
    for (WORD i = 0; i < ntHeaders.FileHeader.NumberOfSections; i++) {
        IMAGE_SECTION_HEADER sectionHeader;
        if (fread(&sectionHeader, sizeof(IMAGE_SECTION_HEADER), 1, file) != 1) {
            fprintf(stderr, "Failed to read section header\n");
            fclose(file);
            return;
        }

        fileSize += sectionHeader.SizeOfRawData;
    }

    printf("Total PE File Size: %lu bytes\n", fileSize);

    // Clean up
    fclose(file);
}

ULONGLONG getPEBaseAddress() {
    return 0ULL;
}

void passProcessInfo() { //creates shared memory to pass ProcessData


    //Shared Memory Name: SHARED_MEMORY_NAME


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


}

void fixIAT() {

}

void loadPE() {

}