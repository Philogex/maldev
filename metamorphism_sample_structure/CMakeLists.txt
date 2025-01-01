cmake_minimum_required(VERSION 3.15)

project(Metamorphic)

# set(CMAKE_VERBOSE_MAKEFILE ON)

# Specify Clang compilers
set(CMAKE_C_COMPILER "clang-16")
set(CMAKE_CXX_COMPILER "clang++-16")

# Set target system and architecture
set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

# Specify Clang flags to target Windows (MinGW-w64)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} --target=x86_64-w64-mingw32")

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
add_library(encryption_pass SHARED ${CMAKE_SOURCE_DIR}/lib/passes/encryption_pass.cpp)

# Set the correct linker language (C++ for the pass)
set_target_properties(encryption_pass PROPERTIES LINKER_LANGUAGE CXX)

# Target-specific include directories for encryption_pass
target_include_directories(encryption_pass PRIVATE ${LLVM_INCLUDE_DIRS})

# Add LLVM 16 Config Definitions to CMake
target_compile_definitions(encryption_pass PRIVATE ${LLVM_DEFINITIONS})

# Generate post-processing executable function_encrypter
add_executable(function_encrypter ${CMAKE_SOURCE_DIR}/lib/utils/function_encrypter.cpp)

# Set the correct linker language (C++ for the executable)
set_target_properties(function_encrypter PROPERTIES 
    LINKER_LANGUAGE CXX
)

# Specify the output directory for the executable
set_target_properties(function_encrypter PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/out"
)

# Set the linker flags for function_encrypter
target_link_options(function_encrypter PRIVATE 
    ""
)

# Include LLVM directories
target_include_directories(function_encrypter PRIVATE ${LLVM_INCLUDE_DIRS})

# Add LLVM 16 Config Definitions to CMake
target_compile_definitions(function_encrypter PRIVATE ${LLVM_DEFINITIONS})

# Get the output from llvm-config for flags and libraries
execute_process(
    COMMAND llvm-config --cxxflags
    OUTPUT_VARIABLE LLVM_CXXFLAGS
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

execute_process(
    COMMAND llvm-config --libs all
    OUTPUT_VARIABLE LLVM_LIBS
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

execute_process(
    COMMAND llvm-config --ldflags
    OUTPUT_VARIABLE LLVM_LDFLAGS
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

# Add compiler flags
target_compile_options(function_encrypter PRIVATE ${LLVM_CXXFLAGS})

# Add linker flags
target_link_options(function_encrypter PRIVATE ${LLVM_LDFLAGS})

# Link the libraries required for linking
target_link_libraries(function_encrypter PRIVATE ${LLVM_LIBS})

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

add_custom_target(linking ALL
    DEPENDS ${CMAKE_BINARY_DIR}/out/program.bc
)

# Apply the encryption_pass shared library on the bitcode
add_custom_command(
    OUTPUT ${CMAKE_BINARY_DIR}/out/main_pass.bc ${CMAKE_BINARY_DIR}/out/pass_output.txt
    COMMAND opt -load-pass-plugin=${CMAKE_BINARY_DIR}/libencryption_pass.so -passes='encryption-pass'
            -o ${CMAKE_BINARY_DIR}/out/main_pass.bc ${CMAKE_BINARY_DIR}/out/program.bc
            2>&1 | tee ${CMAKE_BINARY_DIR}/out/pass_output.txt
    DEPENDS ${CMAKE_BINARY_DIR}/out/program.bc ${CMAKE_BINARY_DIR}/libencryption_pass.so
    COMMENT "Running the encryption_pass on LLVM bitcode"
)

add_custom_target(optimizing ALL
    DEPENDS ${CMAKE_BINARY_DIR}/out/main_pass.bc
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

add_custom_target(executable ALL
    DEPENDS ${CMAKE_BINARY_DIR}/out/metamorphic.exe
)

# Output directory and Linked Language
set_target_properties(executable PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/out"
    LINKER_LANGUAGE C
)

# Custom command to extract strings
add_custom_command(
    OUTPUT ${CMAKE_BINARY_DIR}/out/metamorphic_strings.txt
    COMMAND strings ${CMAKE_BINARY_DIR}/out/metamorphic.exe > ${CMAKE_BINARY_DIR}/out/metamorphic_strings.txt
    COMMENT "Extracting strings from metamorphic.exe"
    DEPENDS ${CMAKE_BINARY_DIR}/out/metamorphic.exe
)

# Custom command to generate disassembly
add_custom_command(
    OUTPUT ${CMAKE_BINARY_DIR}/out/metamorphic_disasm.txt
    COMMAND objdump -d ${CMAKE_BINARY_DIR}/out/metamorphic.exe > ${CMAKE_BINARY_DIR}/out/metamorphic_disasm.txt
    COMMENT "Generating disassembly of metamorphic.exe"
    DEPENDS ${CMAKE_BINARY_DIR}/out/metamorphic.exe
)

# Custom command to strip the executable
add_custom_command(
    OUTPUT ${CMAKE_BINARY_DIR}/out/metamorphic_stripped.exe
    COMMAND strip ${CMAKE_BINARY_DIR}/out/metamorphic.exe -o ${CMAKE_BINARY_DIR}/out/metamorphic_stripped.exe
    COMMENT "Stripping metamorphic.exe"
    DEPENDS ${CMAKE_BINARY_DIR}/out/metamorphic.exe
)

# Custom command to generate IR of the Bitcode
add_custom_command(
    OUTPUT ${CMAKE_BINARY_DIR}/out/metamorphic_ir.ir
    COMMAND llvm-dis ${CMAKE_BINARY_DIR}/out/main_pass.bc -o ${CMAKE_BINARY_DIR}/out/metamorphic_ir.ir
    COMMENT "Generating IR for metamorphic.exe"
    DEPENDS ${CMAKE_BINARY_DIR}/out/main_pass.bc
)

# Custom command to encrypt functions
add_custom_command(
    OUTPUT ${CMAKE_BINARY_DIR}/out/metamorphic_encrypted.exe
    COMMAND ${CMAKE_BINARY_DIR}/out/function_encrypter ${CMAKE_BINARY_DIR}/out/metamorphic.exe ${CMAKE_BINARY_DIR}/out/metamorphic_encrypted.exe "0xAA"
    COMMENT "Encrypting Functions of metamorphic.exe"
    DEPENDS 
        ${CMAKE_BINARY_DIR}/out/metamorphic.exe
        ${CMAKE_BINARY_DIR}/out/function_encrypter
)

# Custom target to group all post-build commands
add_custom_target(encrypt_functions ALL
    DEPENDS ${CMAKE_BINARY_DIR}/out/metamorphic_encrypted.exe
)

# Custom target to group all post-build commands
add_custom_target(post_build_commands ALL
    DEPENDS 
        ${CMAKE_SOURCE_DIR}/out/metamorphic_strings.txt 
        ${CMAKE_SOURCE_DIR}/out/metamorphic_disasm.txt
        ${CMAKE_SOURCE_DIR}/out/metamorphic_stripped.exe
        ${CMAKE_SOURCE_DIR}/out/metamorphic_ir.ir
        ${CMAKE_SOURCE_DIR}/out/metamorphic.exe
        ${CMAKE_SOURCE_DIR}/out/metamorphic_encrypted.exe
        ${CMAKE_SOURCE_DIR}/out/function_encrypter
)

# List of files to copy to the output directory
set(INPUT_FILES
    ${CMAKE_BINARY_DIR}/out/metamorphic.exe
    ${CMAKE_BINARY_DIR}/out/metamorphic_encrypted.exe
    ${CMAKE_BINARY_DIR}/out/metamorphic_stripped.exe
    ${CMAKE_BINARY_DIR}/out/metamorphic_disasm.txt
    ${CMAKE_BINARY_DIR}/out/metamorphic_strings.txt
    ${CMAKE_BINARY_DIR}/out/function_encrypter
    ${CMAKE_BINARY_DIR}/out/metamorphic_ir.ir
)

# Custom command to copy all output files to a new location (e.g., ../out/)
add_custom_command(
    OUTPUT 
        ${CMAKE_SOURCE_DIR}/out/metamorphic.exe
        ${CMAKE_SOURCE_DIR}/out/metamorphic_encrypted.exe
        ${CMAKE_SOURCE_DIR}/out/metamorphic_stripped.exe
        ${CMAKE_SOURCE_DIR}/out/metamorphic_disasm.txt
        ${CMAKE_SOURCE_DIR}/out/metamorphic_strings.txt
        ${CMAKE_SOURCE_DIR}/out/function_encrypter
        ${CMAKE_SOURCE_DIR}/out/metamorphic_ir.ir
    COMMAND ${CMAKE_COMMAND} -E copy ${INPUT_FILES} ${CMAKE_SOURCE_DIR}/out/
    COMMENT "Copying files to the final output directory"
    DEPENDS 
        ${CMAKE_BINARY_DIR}/out/metamorphic_strings.txt 
        ${CMAKE_BINARY_DIR}/out/metamorphic_disasm.txt
        ${CMAKE_BINARY_DIR}/out/metamorphic_stripped.exe
        ${CMAKE_BINARY_DIR}/out/metamorphic_ir.ir
        ${CMAKE_BINARY_DIR}/out/metamorphic.exe
        ${CMAKE_BINARY_DIR}/out/metamorphic_encrypted.exe
        ${CMAKE_BINARY_DIR}/out/function_encrypter
)