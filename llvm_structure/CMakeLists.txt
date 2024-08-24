cmake_minimum_required(VERSION 3.10)
project(LLVM_Testing LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# clang-toolchain.cmake
set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

# Specify Clang compiler
set(CMAKE_C_COMPILER "clang")
set(CMAKE_CXX_COMPILER "clang++")

# Specify the target triple and sysroot
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} --target=x86_64-w64-mingw32 -I /usr/lib/gcc/x86_64-w64-mingw32/13-win32/include/ -I /usr/x86_64-w64-mingw32/include/")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} --target=x86_64-w64-mingw32 -I /usr/lib/gcc/x86_64-w64-mingw32/13-win32/include/c++/x86_64-w64-mingw32/ -I /usr/lib/gcc/x86_64-w64-mingw32/13-win32/include/c++/ -I /usr/x86_64-w64-mingw32/include/")

# Set include and library directories
include_directories("/usr/x86_64-w64-mingw32/include")
link_directories("/usr/lib/gcc/x86_64-w64-mingw32/13-win32/")

# Manually set the LLVM include and library directories
include_directories("/usr/include/llvm-17/")
include_directories("/usr/include/llvm-17/llvm/")
include_directories("/usr/include/llvm-c-17/")
include_directories("/usr/include/llvm-c-17/llvm-c/")
link_directories("/usr/lib/llvm-17/lib/")

# Define linker flags
set(CMAKE_EXE_LINKER_FLAGS "-static-libgcc -static-libstdc++")

# Define output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Define the source files
file(GLOB SOURCES "src/*.cpp")

# Add executable target
add_executable(win64_llvm ${SOURCES})

# Link against specific LLVM libraries
target_link_libraries(win64_llvm
    LLVMCore
    LLVMSupport
    LLVMTarget
    LLVMAnalysis
    LLVMTransformUtils
    LLVMX86CodeGen
    LLVMX86Desc
    LLVMX86Info
    LLVMX86Disassembler
)

# Add the passes subdirectory
# add_subdirectory(src/passes)