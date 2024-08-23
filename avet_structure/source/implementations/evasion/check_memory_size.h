#pragma once

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

void check_memory_size(char *arg1) {
    u_int64 memory_tolerance = 4;
    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(MEMORYSTATUSEX);
    GlobalMemoryStatusEx(&memInfo);

    //Total Memory as MB //memInfo.ullTotalPhys
    if(memInfo.ullAvailPhys / 1024 / 1024 <= memory_tolerance) {
        exit(0);
    }
}