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
clang++ -S -emit-llvm -target x86_64-w64-mingw32 -I/usr/lib/gcc/x86_64-w64-mingw32/13-win32/include/c++/x86_64-w64-mingw32/ -I/usr/lib/gcc/x86_64-w64-mingw32/13-win32/include/c++/ -I/usr/x86_64-w64-mingw32/include/ ../src/*.cpp
llvm-link -o win64_llvm.bc *.ll

# Navigate to the project build directory
cd ../lib/passes/build

# Set clang as compiler before running cmake
export CC=/usr/lib/llvm-17/bin/clang
export CXX=/usr/lib/llvm-17/bin/clang

# Compile "MyPass" into a shared library
echo "Building MyPass into shared library"
cmake -G "Ninja" ../
cmake --build .

# Navigate to the project build directory
cd ../../../build

# Running custom llvm pass on project bytecode
# echo "Running custom llvm pass on project bc"
# opt -load-pass-plugin ./../lib/passes/build/libMyPass.so -passes="my-pass" < win64_llvm.bc > /dev/null

# Run CMake with Ninja for cross-compilation
# cmake -G "Ninja" ..

# Build the project
# cmake --build .

# Placeholder until i fix CMake Pipeline
echo "Generating executable to out dir"
clang++ -Wno-unused-command-line-argument --target=x86_64-w64-mingw32 -L/usr/lib/gcc/x86_64-w64-mingw32/13-win32/ -static-libgcc -static-libstdc++ -o ../out/win64_llvm win64_llvm.bc

# Return to the project root directory
cd ..