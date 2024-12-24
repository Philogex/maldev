cmake_minimum_required(VERSION 3.15)
project(Metamorphic C)

# Set up the cross-compilation toolchain
# set(CMAKE_C_COMPILER "clang")
# set(CMAKE_CXX_COMPILER "clang++")

# Set target system and architecture for cross-compilation to Windows
set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

# Set the MinGW cross-compilation paths (adjust these paths as necessary)
set(MINGW_PATH "/usr/x86_64-w64-mingw32")
set(CMAKE_C_COMPILER "/usr/bin/x86_64-w64-mingw32-gcc")
set(CMAKE_CXX_COMPILER "/usr/bin/x86_64-w64-mingw32-g++")

# Set the flags for Clang to target Windows (ensure static linking)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} --target=x86_64-w64-mingw32")
set(CMAKE_EXE_LINKER_FLAGS "-static-libgcc -static-libstdc++")

# Set include directories for MinGW (modify if necessary)
include_directories(
    /usr/lib/gcc/x86_64-w64-mingw32/13-win32/include/c++/x86_64-w64-mingw32/
    /usr/lib/gcc/x86_64-w64-mingw32/13-win32/include/c++/
    /usr/x86_64-w64-mingw32/include/
)

# Set source files (adjust these paths if needed)
set(SOURCE_FILES
    src/core/main.c
    src/core/control_flow_handler.c
    src/core/cryptor.c
    src/core/instruction_substitutor.c
    src/data/adjacency_table.h
    src/data/adjacency_table.c
    src/data/config.h
    src/data/config.c
)

# Define the output executable
add_executable(metamorphic ${SOURCE_FILES})

# Set output directory for the final executable
set_target_properties(metamorphic PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/out"
)

# Optional: Add a custom target for stripping and other post-build actions
add_custom_target(post_build_commands
    COMMAND strip ${CMAKE_BINARY_DIR}/out/metamorphic.exe
    COMMAND strings ${CMAKE_BINARY_DIR}/out/metamorphic.exe > ${CMAKE_BINARY_DIR}/out/metamorphic_strings.txt
    COMMAND objdump -d ${CMAKE_BINARY_DIR}/out/metamorphic.exe > ${CMAKE_BINARY_DIR}/out/metamorphic_disasm.txt
    COMMENT "Post-build actions like stripping, disassembling, and string extraction"
)

# Optionally, if you need to run custom steps, use add_custom_command or add_custom_target
# For example, you can use `add_custom_command` to run additional post-processing on the binary.
