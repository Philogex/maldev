cmake_minimum_required(VERSION 3.10)
project(LLVM_Testing LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Specify Clang toolchain
set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

# Specify Clang compiler
set(CMAKE_C_COMPILER "clang")
set(CMAKE_CXX_COMPILER "clang++")

# Define output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Define the bitcode file
file(GLOB BITCODE_FILE "win64_llvm.bc")

# Add custom command to link the bitcode file
add_custom_command(
  OUTPUT ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/win64_llvm
  COMMAND clang++ --target=x86_64-w64-mingw32
                  -I /usr/lib/gcc/x86_64-w64-mingw32/13-win32/include/c++/x86_64-w64-mingw32/
                  -I /usr/lib/gcc/x86_64-w64-mingw32/13-win32/include/c++/
                  -I /usr/x86_64-w64-mingw32/include/
                  -static-libgcc -static-libstdc++
                  -o ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/win64_llvm ${BITCODE_FILE}
  DEPENDS ${BITCODE_FILE}
  COMMENT "Linking LLVM bitcode file to executable"
)

# Add custom target to build the executable
add_custom_target(
  build_executable
  DEPENDS ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/win64_llvm
)