#!/bin/bash

length=80
divider_character="="

printf '%*s\n' "$length" '' | tr ' ' "$divider_character"

# Very important
cat ../cat.txt

printf '%*s\n' "$length" '' | tr ' ' "$divider_character"

# Clean project files until i setup other checks to prevent warnings and errors
./clean.sh

# Check if cmake is installed, if not, run install.sh
if ! command -v cmake &> /dev/null; then
    echo "CMake is not installed. Installing required packages..."
    ./install.sh
fi

# Navigate to the project build directory
cd build

printf '%*s\n' "$length" '' | tr ' ' "$divider_character"

# Generate IR and link all source files
echo "Generating IR and linking sources"
clang++ -S -emit-llvm --target=x86_64-w64-mingw32 -I/usr/lib/gcc/x86_64-w64-mingw32/13-win32/include/c++/x86_64-w64-mingw32/ -I/usr/lib/gcc/x86_64-w64-mingw32/13-win32/include/c++/ -I/usr/x86_64-w64-mingw32/include/ ../src/*.cpp
llvm-link -o win64_llvm.bc *.ll
llvm-dis -o win64_llvm.ll win64_llvm.bc # holy shit im actually balding after this. why does it only work on .ll files even tho clang has support for both .bc as well as .ll files

# Navigate to the project build directory
cd ../lib/passes/build

# Set clang as compiler before running cmake
export CC=/usr/lib/llvm-17/bin/clang
export CXX=/usr/lib/llvm-17/bin/clang

printf '%*s\n' "$length" '' | tr ' ' "$divider_character"

# Compile "MyPass" into a shared library
echo "Building MyPass into shared library"
cmake -G "Ninja" ../
cmake --build .

# Navigate to the project build directory
cd ../../../build

printf '%*s\n' "$length" '' | tr ' ' "$divider_character"

# Running custom llvm pass on project IR
echo "Running custom llvm pipeline on project .ll ..."
opt -load-pass-plugin=./../lib/passes/build/libMyPass.so -p my-pass -S < win64_llvm.ll > win64_llvm_transform.ll # i also just read the opt --help. god damn i love the polly options, but we are not here to optimize
# opt -load-pass-plugin=<other pass> -passes="<pass name>" -S < win64_llvm_transform.ll > win64_llvm_transform.ll
echo "Finished running custom llvm pipeline on project .ll"

# Run CMake with Ninja for cross-compilation
# cmake -G "Ninja" ..

# Build the project
# cmake --build .

printf '%*s\n' "$length" '' | tr ' ' "$divider_character"

# Placeholder until i fix CMake pipeline
echo "Generating executable from transform.ll ..."
clang++ -Wno-unused-command-line-argument --target=x86_64-w64-mingw32 -L/usr/lib/gcc/x86_64-w64-mingw32/13-win32/ -static-libgcc -static-libstdc++ -o ../out/win64_llvm win64_llvm_transform.ll
echo "Finished generating executable"

# Return to the project root directory
cd ..

printf '%*s\n' "$length" '' | tr ' ' "$divider_character"

# Check Project files
exiftool out/win64_llvm.exe > out/win64_llvm_exif.txt
cat out/win64_llvm_exif.txt

printf '%*s\n' "$length" '' | tr ' ' "$divider_character"

strip out/win64_llvm.exe

strings out/win64_llvm.exe > out/win64_llvm_strings.txt
objdump -d out/win64_llvm.exe > out/win64_llvm_disasm.txt

clang++ -O0 -Wno-unused-command-line-argument --target=x86_64-w64-mingw32 -L/usr/lib/gcc/x86_64-w64-mingw32/13-win32/ -static-libgcc -static-libstdc++ -o out/win64_llvm_O0.s build/win64_llvm_transform.ll -S
clang++ -O2 -Wno-unused-command-line-argument --target=x86_64-w64-mingw32 -L/usr/lib/gcc/x86_64-w64-mingw32/13-win32/ -static-libgcc -static-libstdc++ -o out/win64_llvm_O2.s build/win64_llvm_transform.ll -S
echo "Checking diff..."
diff out/win64_llvm_O0.s out/win64_llvm_O2.s
if [ $? -eq 0 ]; then
  echo "O0 and O2 are the same"
else
  echo "Code would be optimized by O2"
fi

printf '%*s\n' "$length" '' | tr ' ' "$divider_character"