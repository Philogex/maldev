#pragma once

#include <windows.h>

void block_input( char *arg1 ) {
    if (BlockInput(TRUE)) {
        return;
    } else {
        exit(0);
    }
}