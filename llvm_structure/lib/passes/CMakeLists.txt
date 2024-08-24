cmake_minimum_required(VERSION 3.10)
project(MyPass)

# Set policy CMP0075 to NEW to handle include file checks as per CMake 3.11 and above
if(POLICY CMP0075)
  cmake_policy(SET CMP0075 NEW)
endif()

find_package(LLVM 17 REQUIRED CONFIG)

include_directories(${LLVM_INCLUDE_DIRS})
add_definitions(${LLVM_DEFINITIONS})

add_library(MyPass MODULE MyPass.cpp)

target_link_libraries(MyPass PRIVATE LLVMCore LLVMSupport)