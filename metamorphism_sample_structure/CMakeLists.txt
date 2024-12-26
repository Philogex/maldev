cmake_minimum_required(VERSION 3.15)
project(Metamorphic C)

# set(CMAKE_VERBOSE_MAKEFILE ON)

# Specify Clang compilers
set(CMAKE_C_COMPILER "clang-16")
set(CMAKE_CXX_COMPILER "clang++-16")

# Set target system and architecture
set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

# Specify Clang flags to target Windows (MinGW-w64)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} --target=x86_64-w64-mingw32")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} --target=x86_64-w64-mingw32")
set(CMAKE_EXE_LINKER_FLAGS "-static")

# Include MinGW headers and libraries
include_directories(
    /usr/lib/gcc/x86_64-w64-mingw32/13-win32/include/c++/x86_64-w64-mingw32/
    /usr/lib/gcc/x86_64-w64-mingw32/13-win32/include/c++/
    /usr/x86_64-w64-mingw32/include/
)

link_directories(
    /usr/lib/gcc/x86_64-w64-mingw32/13-win32/
    /usr/x86_64-w64-mingw32/lib/
)

# Source files
set(SOURCE_FILES
    src/core/main.c
    src/core/c2_handler.c
    src/core/control_flow_handler.h
    src/core/control_flow_handler.c
    src/core/cryptor.h
    src/core/cryptor.c
    src/core/instruction_substitutor.c
    src/data/adjacency_table.h
    src/data/adjacency_table.c
    src/data/config.h
    src/data/config.c
    src/crypto/aes.h
    src/crypto/kdf.h
    src/crypto/rsa.h
)

# Compile sources into LLVM bitcode
add_custom_command(
    OUTPUT ${CMAKE_BINARY_DIR}/out/main.bc
    COMMAND clang -S -emit-llvm -o ${CMAKE_BINARY_DIR}/out/main.bc
            ${SOURCE_FILES} --target=x86_64-w64-mingw32 -I/usr/x86_64-w64-mingw32/include/
    COMMENT "Generating LLVM bitcode for main sources"
)

# Add Correct LLVM Version to CMake Module Path
list(APPEND CMAKE_MODULE_PATH "/usr/lib/llvm-16/lib/cmake/llvm") # llvm version needs to match clang and opt
include(AddLLVM)

# Set policy CMP0075 to NEW to handle include file checks as per CMake 3.11 and above
if(POLICY CMP0075)
  cmake_policy(SET CMP0075 NEW)
endif()

# Import LLVM 16 Config
find_package(LLVM 16 REQUIRED CONFIG)

# Add LLVM 16 Config Definitions to CMake
separate_arguments(LLVM_DEFINITIONS_LIST NATIVE_COMMAND ${LLVM_DEFINITIONS})
add_definitions(${LLVM_DEFINITIONS})
include_directories(${LLVM_INCLUDE_DIRS})

# Create shared library for LLVM pass
add_library(encryption_pass SHARED lib/encryption_pass.cpp)

# Set the correct linker language (C++ for the pass)
set_target_properties(encryption_pass PROPERTIES LINKER_LANGUAGE CXX)

# Apply the encryption_pass shared library on the bitcode
add_custom_command(
    OUTPUT ${CMAKE_BINARY_DIR}/out/main_pass.bc
    COMMAND opt -load ${CMAKE_BINARY_DIR}/libencryption_pass.so -encryption-pass
            -o ${CMAKE_BINARY_DIR}/out/main_pass.bc ${CMAKE_BINARY_DIR}/out/main.bc
    COMMENT "Running the encryption_pass on LLVM bitcode"
)

# Link the transformed bitcode into an executable
add_custom_command(
    OUTPUT ${CMAKE_BINARY_DIR}/out/metamorphic.exe
    COMMAND clang -o ${CMAKE_BINARY_DIR}/out/metamorphic.exe
            ${CMAKE_BINARY_DIR}/out/main_pass.bc --target=x86_64-w64-mingw32 -static
    COMMENT "Linking final executable from transformed LLVM bitcode"
)

# Add a custom target to trigger the whole pipeline
add_custom_target(
    run_encryption_pass
    DEPENDS ${CMAKE_BINARY_DIR}/out/metamorphic.exe
    COMMENT "Pipeline: Generate Bitcode -> Apply Pass -> Produce Executable"
)

# Output executable
add_executable(metamorphic ${SOURCE_FILES})

# Output directory
set_target_properties(metamorphic PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/out"
)

# Post-build commands
add_custom_target(post_build_commands
    COMMAND strip ${CMAKE_BINARY_DIR}/out/metamorphic.exe
    COMMAND strings ${CMAKE_BINARY_DIR}/out/metamorphic.exe > ${CMAKE_BINARY_DIR}/out/metamorphic_strings.txt
    COMMAND objdump -d ${CMAKE_BINARY_DIR}/out/metamorphic.exe > ${CMAKE_BINARY_DIR}/out/metamorphic_disasm.txt
    COMMENT "Post-build actions: stripping, disassembling, and string extraction"
)