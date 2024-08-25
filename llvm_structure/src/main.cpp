// src/main.cpp
#include <iostream>
#include <windows.h>
#include "../include/example.h"

int main() {
    // String example
    std::cout << "Hello, World!" << std::endl;

    // Optimization check
    volatile int x = 42;
    int y = x * 2;

    // External function check
    exampleFunction();
    return 0;
}