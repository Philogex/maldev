// src/main.cpp
#include <iostream>
#include <windows.h>
#include <cstring>
#include "../include/control_flow_node.h"

int main();

int main() {
    // Initialize control flow map object for later reference
    control_flow_obfuscation::init_control_flow_map();

    // Example: Allocate memory for executable code
    void* execMemory = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!execMemory) {
        std::cerr << "Failed to allocate memory!" << std::endl;
        return 1;
    }

    // Write machine code into memory
    // mov eax, 42; ret
    unsigned char code[] = {
        0xB8, 0x2A, 0x00, 0x00, 0x00, // mov eax, 42
        0xC3                          // ret
    };
    memcpy(execMemory, code, sizeof(code));

    // Define function pointer and execute
    using FuncType = int (*)();
    FuncType dynamicFunc = (FuncType)execMemory;
    int result = dynamicFunc();

    std::cout << "Dynamic function returned: " << result << std::endl;

    // Clean up
    VirtualFree(execMemory, 0, MEM_RELEASE);

    // Start with a specific function
    control_flow_obfuscation::FuncPtr currentFunc = &control_flow_obfuscation::fun1;
    while (currentFunc) {
        // Execute the current function
        currentFunc();

        // Get the next function based on control flow
        currentFunc = control_flow_obfuscation::get_control_flow(currentFunc);
    }

    return 0;
}