#!/bin/bash

# Very Important
cat ../cat.txt

# Check if cmake is installed, if not, run install.sh
if ! command -v cmake &> /dev/null; then
    echo "CMake is not installed. Installing required packages..."
    ./install.sh
fi

# Navigate to the project build directory
cd build

# Generate IR and link all source files
echo "Generating IR and linking sources"
clang++ -S -emit-llvm ../src/*.cpp
llvm-link -o ../out/win64_llvm.bc *.ll

# Navigate to the project build directory
cd ../lib/passes/build

# Compile "MyPass" into a shared library
echo "Building MyPass into shared library"
cmake -G "Ninja" ../
cmake --build .

# Navigate to the project build directory
cd ../../../build

# Running custom llvm pass on project bytecode
echo "Running custom llvm pass on project bc"
opt -load-pass-plugin ./../lib/passes/build/libMyPass.so -passes="my-pass" < ../out/win64_llvm.bc > /dev/null

# Run CMake with Ninja for cross-compilation
#cmake -G "Ninja" ..

# Build the project
#cmake --build .

# Return to the project root directory
#cd ..