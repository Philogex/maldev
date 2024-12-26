cmake_minimum_required(VERSION 3.15)
project(Metamorphic C)

# Specify Clang compilers
set(CMAKE_C_COMPILER "clang")
set(CMAKE_CXX_COMPILER "clang++")

# Set target system and architecture
set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

# Specify Clang flags to target Windows
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
