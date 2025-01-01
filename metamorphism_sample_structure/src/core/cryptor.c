/*
func decrypt_control_flow
func encrypt_control_flow

func overwrite_disk_binary
*/

#include "cryptor.h"

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

// this is copy pasted from somewhere... i don't know from where
// found it: https://gist.github.com/Niko10/c96eb7330f81b1c8a2473665af9c0379
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

FunctionInfo* analyzeExecutable(size_t* functionCount) {
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

    ULONGLONG textSectionVA = 0;
    DWORD textSectionSize = 0;

    for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        if (strncmp((char *)pSectionHeader[i].Name, ".text", 5) == 0) {
            textSectionVA = pSectionHeader[i].VirtualAddress;
            textSectionSize = pSectionHeader[i].SizeOfRawData;
            break;
        }
    }

    if (textSectionVA == 0) {
        printf("Error: .text section not found.\n");
        return NULL;
    }

    printf("Text Section Address: 0x%llX, Size: %lX bytes\n", textSectionVA, textSectionSize);

    DWORD* functionRVAs = malloc(sizeof(DWORD) * 1024); // Temporary storage for function RVAs
    size_t functionRVAIndex = 0;





    // MISSING (Parse Metadata from Header)





    ULONGLONG test = Rva2Offset(textSectionVA + (DWORD)0x9d0, baseAddress);
    printf("Testing Rva2Offset: 0x%llX\n", test);

    *functionCount = functionRVAIndex;

    // Return the list of functions (if we were to fill functionList here)
    // Note: The function list is currently not fully implemented here
    return NULL;  // Function list would be returned here once populated
}

void decrypt_function(const unsigned char *encrypted, size_t size) {
    
}

void encrypt_function(const unsigned char *decrypted, size_t size) {
    
}