#pragma once


#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

typedef LONG (NTAPI *NtDelayExecution_t)(BOOL Alertable, PLARGE_INTEGER DelayInterval);
typedef LONG (NTAPI *NtQuerySystemTime_t)(PLARGE_INTEGER SystemTime);

void SleepUsingSyscall(DWORD milliseconds) {
    const char ntdll_dll[] = {'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l', 0};
    
    HMODULE ntdll = LoadLibraryA(ntdll_dll);
    if (ntdll == NULL) {
        return;
    }

    const char nt_delay_execution[] = {'N', 't', 'D', 'e', 'l', 'a', 'y', 'E', 'x', 'e', 'c', 'u', 't', 'i', 'o', 'n', 0};
    NtDelayExecution_t NtDelayExecution = (NtDelayExecution_t)GetProcAddress(ntdll, nt_delay_execution);
    if (NtDelayExecution == NULL) {
        FreeLibrary(ntdll);
        return;
    }

    LARGE_INTEGER interval;
    interval.QuadPart = -1 * (LONGLONG)milliseconds * 10000;

    NtDelayExecution(FALSE, &interval);

    FreeLibrary(ntdll);
}

void GetLocalTimeUsingSyscall(SYSTEMTIME *systemTime) {
    char ntdll_dll[] = {'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l', '\0'};

    HMODULE ntdll = LoadLibraryA(ntdll_dll);
    if (ntdll == NULL) {
        return;
    }

    const char nt_query_system_time[] = {'N','t','Q','u','e','r','y','S','y','s','t','e','m','T','i','m','e' , 0};
    NtQuerySystemTime_t NtQuerySystemTime = (NtQuerySystemTime_t)GetProcAddress(ntdll, nt_query_system_time);
    if (NtQuerySystemTime == NULL) {
        FreeLibrary(ntdll);
        return;
    }

    LARGE_INTEGER currentTime;
    SYSTEMTIME localTime;

    NTSTATUS status = NtQuerySystemTime(&currentTime);
    if (status != 0) {
        FreeLibrary(ntdll);
        return;
    }

    FileTimeToSystemTime((FILETIME *)&currentTime, &localTime);

    memcpy(systemTime, &localTime, sizeof(SYSTEMTIME));

    FreeLibrary(ntdll);
}

DWORDLONG Delta(const SYSTEMTIME st1, const SYSTEMTIME st2) {
    union timeunion
    {
        FILETIME fileTime;
        ULARGE_INTEGER ul;
    };

    FILETIME ft1;
    FILETIME ft2;

    SystemTimeToFileTime(&st1, &ft1);
    SystemTimeToFileTime(&st2, &ft2);

    ULARGE_INTEGER u1 = {0};
    ULARGE_INTEGER u2 = {0};

    memcpy(&u1, &ft1, sizeof(u1));
    memcpy(&u2, &ft2, sizeof(u2));

    return u2.QuadPart - u1.QuadPart;
}

// Check if sandbox utilize fast forwarding to reduce heuristic check time
//
// Get time before and after sleep and calculate the difference
// If the difference and specified sleep time match, we proceed
// arg1:        time in Seconds
void check_fast_forwarding_no_winapi(char *arg1) {
    //DEBUG_PRINT("Applying check_fast_forwarding technique.\n");

    SYSTEMTIME before_sleep;
    SYSTEMTIME after_sleep;

    GetLocalTimeUsingSyscall(&before_sleep);

    //DEBUG_PRINT("Time before sleep: %d:%d:%d", before_sleep.wHour, before_sleep.wMinute, before_sleep.wSecond);
    //DEBUG_PRINT("Sleeping for %s Seconds...\n", arg1);

    int time = atoi(arg1);
    SleepUsingSyscall(time * 1000);

    GetLocalTimeUsingSyscall(&after_sleep);

    DWORDLONG delta = Delta(before_sleep, after_sleep);

    //DEBUG_PRINT("Time difference %s Seconds...\n", i/10000000);

    DWORDLONG expected_time = time * 10000000ULL;
    DWORDLONG tolerance = 600 * 10000; // 1 ms

    if (delta >= expected_time - tolerance && delta <= expected_time + tolerance) {
        //DEBUG_PRINT("Proceed!\n");
    } else {
        exit(0);
    }
}
