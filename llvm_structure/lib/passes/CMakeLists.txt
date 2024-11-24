cmake_minimum_required(VERSION 3.10)
project(TestPass)

list(APPEND CMAKE_MODULE_PATH "/usr/lib/llvm-16/lib/cmake/llvm") # llvm version needs to match clang and opt
include(AddLLVM)

# Set policy CMP0075 to NEW to handle include file checks as per CMake 3.11 and above
if(POLICY CMP0075)
  cmake_policy(SET CMP0075 NEW)
endif()

find_package(LLVM 16 REQUIRED CONFIG)

separate_arguments(LLVM_DEFINITIONS_LIST NATIVE_COMMAND ${LLVM_DEFINITIONS})
add_definitions(${LLVM_DEFINITIONS})
include_directories(${LLVM_INCLUDE_DIRS})

add_library(TestPass SHARED TestPass.cpp)

# add_library(TestPass MODULE TestPass.cpp)

# add_llvm_library(TestPass MODULE TestPass.cpp PLUGIN_TOOL opt) # might revert to this option later on

# target_link_libraries(TestPass PRIVATE LLVMCore LLVMSupport) # this links into llvm directly, but we already invoke directly using opt, which would cause duplicates