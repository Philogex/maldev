#!/bin/bash

# Very Important
cat ../cat.txt

# Check if cmake is installed, if not, run install.sh
if ! command -v cmake &> /dev/null; then
    echo "CMake is not installed. Installing required packages..."
    ./install.sh
fi

# Create and navigate to the build directory
mkdir -p build
cd build

# Run CMake with Ninja for cross-compilation
cmake -G "Ninja" ..

# Build the project
cmake --build .

# Return to the project root directory
cd ..