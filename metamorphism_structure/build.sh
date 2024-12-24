#!/bin/bash

length=80
divider_character="="

printf '%*s\n' "$length" '' | tr ' ' "$divider_character"

# Print a very important message
cat ../cat.txt

# Print a divider
printf '%*s\n' "$length" '' | tr ' ' "$divider_character"

# Clean project files
./clean.sh

# Check if cmake is installed, if not, run install.sh
if ! command -v cmake &> /dev/null; then
    echo "CMake is not installed. Installing required packages..."
    ./install.sh
fi

# Navigate to the build directory
cd build || { echo "Build directory not found"; exit 1; }

# Print a divider
printf '%*s\n' "$length" '' | tr ' ' "$divider_character"

# Compile main.cpp and dependencies for Windows
echo "Compiling main.cpp and dependencies for Windows..."

clang++ -Wno-unused-command-line-argument \
    --target=x86_64-w64-mingw32 \
    -I/usr/lib/gcc/x86_64-w64-mingw32/13-win32/include/c++/x86_64-w64-mingw32/ \
    -I/usr/lib/gcc/x86_64-w64-mingw32/13-win32/include/c++/ \
    -I/usr/x86_64-w64-mingw32/include/ \
    -L/usr/lib/gcc/x86_64-w64-mingw32/13-win32/ \
    -static-libgcc -static-libstdc++ \
    -o ../out/main.exe ../src/*.cpp

# Check if the compilation was successful
if [ $? -ne 0 ]; then
    echo "Compilation failed."
    exit 1
fi

echo "Compilation successful. Executable created at ../out/main.exe"

# Print a divider
printf '%*s\n' "$length" '' | tr ' ' "$divider_character"

# Analyze the output binary
exiftool ../out/main.exe > ../out/main_exif.txt
cat ../out/main_exif.txt

strip ../out/main.exe

strings ../out/main.exe > ../out/main_strings.txt
objdump -d ../out/main.exe > ../out/main_disasm.txt

# Print a final divider
printf '%*s\n' "$length" '' | tr ' ' "$divider_character"