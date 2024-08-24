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
llvm-dis -o win64_llvm.ll win64_llvm.bc # holy shit im actually balding after this. why does it only work on .ll files even tho clang has support for both .bc as well as .ll files

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

# Running custom llvm pass on project IR
echo "Running custom llvm pipeline on project .ll"
# opt -load-pass-plugin=./../lib/passes/build/libMyPass.so -passes="default<O2>,my-pass" < win64_llvm.bc > /dev/null
opt -load-pass-plugin=./../lib/passes/build/libMyPass.so -passes="my-pass" < win64_llvm.ll > /dev/null
# opt -passes="default<O2>" < win64_llvm.bc > /dev/null
echo "Finished running custom llvm pipeline on project .ll"

# Run CMake with Ninja for cross-compilation
# cmake -G "Ninja" ..

# Build the project
# cmake --build .

# Placeholder until i fix CMake Pipeline
echo "Generating executable..."
clang++ -Wno-unused-command-line-argument --target=x86_64-w64-mingw32 -L/usr/lib/gcc/x86_64-w64-mingw32/13-win32/ -static-libgcc -static-libstdc++ -o ../out/win64_llvm win64_llvm.ll
echo "Generated executable"

# Return to the project root directory
cd ..