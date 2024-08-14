#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <winternl.h>
#include <psapi.h>
#include <stdbool.h>

PVOID get_original_func_addr(const wchar_t *dll, const wchar_t *func) {
    wchar_t dll_path[MAX_PATH];
    wcscpy(dll_path, L"C:\\Windows\\System32\\");
    wcscat(dll_path, dll);

    // Manually load the DLL
    HANDLE dllFile = CreateFileW(dll_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (dllFile == INVALID_HANDLE_VALUE) {
        wprintf(L"Failed to open DLL file: %s\n", dll_path);
        return NULL;
    }

    DWORD dllFileSize = GetFileSize(dllFile, NULL);
    HANDLE hDllFileMapping = CreateFileMappingW(dllFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    if (hDllFileMapping == NULL) {
        CloseHandle(dllFile);
        wprintf(L"Failed to create file mapping\n");
        return NULL;
    }

    PBYTE pDllFileMappingBase = (PBYTE)MapViewOfFile(hDllFileMapping, FILE_MAP_READ, 0, 0, 0);
    if (pDllFileMappingBase == NULL) {
        CloseHandle(hDllFileMapping);
        CloseHandle(dllFile);
        wprintf(L"Failed to map view of file\n");
        return NULL;
    }

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pDllFileMappingBase;
    PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(pDllFileMappingBase + pDosHeader->e_lfanew);
    PIMAGE_OPTIONAL_HEADER pOptionalHeader = (PIMAGE_OPTIONAL_HEADER)&(pNtHeader->OptionalHeader);
    PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(pDllFileMappingBase + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    PULONG pAddressOfFunctions = (PULONG)(pDllFileMappingBase + pExportDirectory->AddressOfFunctions);
    PULONG pAddressOfNames = (PULONG)(pDllFileMappingBase + pExportDirectory->AddressOfNames);
    PUSHORT pAddressOfNameOrdinals = (PUSHORT)(pDllFileMappingBase + pExportDirectory->AddressOfNameOrdinals);

    PVOID pOriginalFunction = NULL;
    for (DWORD i = 0; i < pExportDirectory->NumberOfNames; ++i) {
        PCSTR pFunctionName = (PSTR)(pDllFileMappingBase + pAddressOfNames[i]);
        wchar_t wFunctionName[MAX_PATH];
        mbstowcs(wFunctionName, pFunctionName, strlen(pFunctionName) + 1);
        if (!wcscmp(wFunctionName, func)) {
            pOriginalFunction = (PVOID)(pDllFileMappingBase + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
            break;
        }
    }

    UnmapViewOfFile(pDllFileMappingBase);
    CloseHandle(hDllFileMapping);
    CloseHandle(dllFile);

    return pOriginalFunction;
}

void vodoo_magic() {
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

    const int nr_functions = 4;

    for (int i = 0; i < nr_functions; i++) {
        PVOID pOriginal = get_original_func_addr(dlls[i], funcs[i]);
        if (pOriginal == NULL) {
            wprintf(L"Failed to get original function address for %s in %s\n", funcs[i], dlls[i]);
            continue;
        }

        PVOID pLoaded = GetProcAddress(GetModuleHandleW(dlls[i]), (LPCSTR)funcs[i]);
        if (pLoaded == NULL) {
            wprintf(L"Failed to get loaded function address for %s in %s\n", funcs[i], dlls[i]);
            continue;
        }

        // Unhook DLL
        if (memcmp(pOriginal, pLoaded, 16) != 0) {
            DWORD oldProtection, tempProtection;
            VirtualProtect(pLoaded, 16, PAGE_EXECUTE_READWRITE, &oldProtection);
            memcpy(pLoaded, pOriginal, 16);
            VirtualProtect(pLoaded, 16, oldProtection, &tempProtection);
        }
    }
}