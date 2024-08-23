#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <winternl.h>
#include <psapi.h>
#include <stdbool.h>

PVOID get_original_func_addr(const wchar_t *dll, const char *func) {
    wchar_t dll_path[MAX_PATH];
    wcscpy(dll_path, L"C:\\Windows\\System32\\");
    wcscat(dll_path, dll);

    // Manually load the DLL
    HANDLE dllFile = CreateFileW(dll_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD dllFileSize = GetFileSize(dllFile, NULL);
    HANDLE hDllFileMapping = CreateFileMappingW(dllFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    HANDLE pDllFileMappingBase = MapViewOfFile(hDllFileMapping, FILE_MAP_READ, 0, 0, 0);
    CloseHandle(dllFile);

    // Analyze the DLL
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pDllFileMappingBase;
    PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((PBYTE)pDllFileMappingBase + pDosHeader->e_lfanew);
    PIMAGE_OPTIONAL_HEADER pOptionalHeader = (PIMAGE_OPTIONAL_HEADER)&(pNtHeader->OptionalHeader);
    PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pDllFileMappingBase + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    PULONG pAddressOfFunctions = (PULONG)((PBYTE)pDllFileMappingBase + pExportDirectory->AddressOfFunctions);
    PULONG pAddressOfNames = (PULONG)((PBYTE)pDllFileMappingBase + pExportDirectory->AddressOfNames);
    PUSHORT pAddressOfNameOrdinals = (PUSHORT)((PBYTE)pDllFileMappingBase + pExportDirectory->AddressOfNameOrdinals);

    // Find the original function code
    PVOID pFuncOriginal = NULL;
    for (int i = 0; i < pExportDirectory->NumberOfNames; ++i) {
        PCSTR pFunctionName = (PSTR)((PBYTE)pDllFileMappingBase + pAddressOfNames[i]);
        if (!strcmp(pFunctionName, func)) {
            pFuncOriginal = (PVOID)((PBYTE)pDllFileMappingBase + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
            break;
        }
    }

    return pFuncOriginal;
}


void check_common_loaded_dlls() {
    const wchar_t *dlls[] = {
        L"kernel32.dll",
        L"kernel32.dll",
        L"ntdll.dll",
        L"ntdll.dll"
    };

    const wchar_t *funcs[] = {
        L"CreateFileW",
        L"VirtualProtect",
        L"NtDelayExecution",
        L"NtQuerySystemTime"
    };

    const int nr_functions = sizeof(dlls) / sizeof(dlls[0]);

    for (int i = 0; i < nr_functions; i++) {
        HMODULE hModule = GetModuleHandleW(dlls[i]);
        if (hModule == NULL) {
            wprintf(L"Failed to get module handle for %ls\n", dlls[i]);
            continue;
        }

        char func_name[128];
        wcstombs(func_name, funcs[i], sizeof(func_name));

        PVOID pLoaded = GetProcAddress(hModule, func_name);
        if (pLoaded == NULL) {
            wprintf(L"Failed to get loaded function address for %ls in %ls\n", funcs[i], dlls[i]);
            continue;
        }

        PVOID pOriginal = get_original_func_addr(dlls[i], func_name);
        if (pOriginal == NULL) {
            wprintf(L"Failed to get original function address for %ls in %ls\n", funcs[i], dlls[i]);
            continue;
        }

        if (memcmp(pOriginal, pLoaded, 16)) {
            DWORD oldProtection, tempProtection;
            VirtualProtect(pLoaded, 16, PAGE_EXECUTE_READWRITE, &oldProtection);
            memcpy(pLoaded, pOriginal, 16);
            VirtualProtect(pLoaded, 16, oldProtection, &tempProtection);
        }

        wprintf(L"Successfully checked and unhooked function %ls in %ls\n", funcs[i], dlls[i]);
    }
}