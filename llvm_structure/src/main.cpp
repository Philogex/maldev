// src/main.cpp
#include <iostream>
#include <windows.h>
#include "../include/example.h"

int main();

typedef NTSTATUS (NTAPI *f_NtMapViewOfSection)(HANDLE, HANDLE, PVOID *, ULONG, ULONG, PLARGE_INTEGER, PULONG, ULONG, ULONG, ULONG);

/*
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PSTR lpCmdLine, int nCmdShow)
{
    main();
    return 0;
}
*/

int main() {
    // String example
    std::cout << "Hello, World!" << std::endl;

    // Optimization check
    volatile int x = 42;
    int y = x * 2;

    // External function check
    exampleFunction();

    // Dummy Windows API calls
    f_NtMapViewOfSection lNtMapViewOfSection;
    HMODULE ntdll;

    if (!(ntdll = LoadLibrary(TEXT("ntdll"))))
    {
        return -1;
    }

    lNtMapViewOfSection = (f_NtMapViewOfSection)GetProcAddress(ntdll, "NtMapViewOfSection");
    lNtMapViewOfSection(0,0,0,0,0,0,0,0,0,0);

    return 0;
}

