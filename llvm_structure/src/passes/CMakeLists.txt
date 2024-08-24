# src/passes/CMakeLists.txt

# Specify the required LLVM include directories
include_directories("/usr/include/llvm-17/")
include_directories("/usr/include/llvm-17/llvm")
include_directories("/usr/include/llvm-c-17/")

# Add your pass source files
add_library(test_pass MODULE test_pass.cpp)

# Link against necessary LLVM libraries
target_link_libraries(test_pass PRIVATE
    LLVMCore
    LLVMSupport
    LLVMAnalysis
    LLVMTransformUtils
)

# Ensure LLVM is linked with your pass
set_target_properties(test_pass PROPERTIES
    COMPILE_FLAGS "-DLLVM_ENABLE_ASSERTIONS=ON"
    LINK_FLAGS "-Wl,--no-undefined"
)