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
file(GLOB SOURCE_FILES
    "${CMAKE_SOURCE_DIR}/src/core/*.c"
    "${CMAKE_SOURCE_DIR}/src/data/*.c"
    "${CMAKE_SOURCE_DIR}/src/crypto/*.c"
)

file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/out)

# Compile each source file into LLVM bitcode
set(BITCODE_FILES "")
foreach(src ${SOURCE_FILES})
    get_filename_component(filename_we ${src} NAME_WE)
    
    # Output bitcode file path
    set(bitcode_output ${CMAKE_BINARY_DIR}/out/${filename_we}.bc)
    
    list(APPEND BITCODE_FILES ${bitcode_output})
    
    add_custom_command(
        OUTPUT ${bitcode_output}
        COMMAND clang -c -emit-llvm --target=x86_64-w64-mingw32 -I/usr/x86_64-w64-mingw32/include/ ${src} -o ${bitcode_output}
        DEPENDS ${src}
        COMMENT "Generating LLVM bitcode for ${src}"
    )
endforeach()

# Link all bitcode files into one bitcode file
add_custom_command(
    OUTPUT ${CMAKE_BINARY_DIR}/out/program.bc
    COMMAND llvm-link -o ${CMAKE_BINARY_DIR}/out/program.bc ${BITCODE_FILES}
    DEPENDS ${BITCODE_FILES}
    COMMENT "Linking LLVM bitcode files"
)

# Apply the encryption_pass shared library on the bitcode
add_custom_command(
    OUTPUT ${CMAKE_BINARY_DIR}/out/main_pass.bc
    COMMAND opt -load-pass-plugin=${CMAKE_BINARY_DIR}/libencryption_pass.so -p encryption-pass
            -o ${CMAKE_BINARY_DIR}/out/main_pass.bc ${CMAKE_BINARY_DIR}/out/program.bc
    DEPENDS ${CMAKE_BINARY_DIR}/out/program.bc ${CMAKE_BINARY_DIR}/libencryption_pass.so
    COMMENT "Running the encryption_pass on LLVM bitcode"
)

# Output executable
# add_executable(metamorphic ${SOURCE_FILES})
# Link the transformed bitcode into an executable
add_custom_command(
    OUTPUT ${CMAKE_BINARY_DIR}/out/metamorphic.exe
    COMMAND clang --target=x86_64-w64-mingw32 -L/usr/lib/gcc/x86_64-w64-mingw32/13-win32/ -static-libgcc -o ${CMAKE_BINARY_DIR}/out/metamorphic.exe ${CMAKE_BINARY_DIR}/out/main_pass.bc
    DEPENDS ${CMAKE_BINARY_DIR}/out/main_pass.bc
    COMMENT "Linking final executable from transformed LLVM bitcode"
)

add_custom_target(metamorphic ALL
    DEPENDS ${CMAKE_BINARY_DIR}/out/metamorphic.exe
)

# Output directory and Linked Language
set_target_properties(metamorphic PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/out"
    LINKER_LANGUAGE C
)

# Post-build actions after building the executable
add_custom_target(post_build_commands ALL
    COMMAND strip ${CMAKE_BINARY_DIR}/out/metamorphic.exe
    COMMAND strings ${CMAKE_BINARY_DIR}/out/metamorphic.exe > ${CMAKE_BINARY_DIR}/out/metamorphic_strings.txt
    COMMAND objdump -d ${CMAKE_BINARY_DIR}/out/metamorphic.exe > ${CMAKE_BINARY_DIR}/out/metamorphic_disasm.txt
    COMMENT "Post-build actions: stripping, disassembling, and string extraction"
    DEPENDS ${CMAKE_BINARY_DIR}/out/metamorphic.exe
)