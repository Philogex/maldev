# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.30

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/kali/Desktop/maldev/metamorphism_sample_structure

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/kali/Desktop/maldev/metamorphism_sample_structure/build

# Utility rule file for executable.

# Include any custom commands dependencies for this target.
include CMakeFiles/executable.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/executable.dir/progress.make

CMakeFiles/executable: out/metamorphic.exe

out/metamorphic.exe: out/main_pass.bc
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --blue --bold --progress-dir=/home/kali/Desktop/maldev/metamorphism_sample_structure/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Linking final executable from transformed LLVM bitcode"
	clang --target=x86_64-w64-mingw32 -L/usr/lib/gcc/x86_64-w64-mingw32/13-win32/ -static-libgcc -o /home/kali/Desktop/maldev/metamorphism_sample_structure/build/out/metamorphic.exe /home/kali/Desktop/maldev/metamorphism_sample_structure/build/out/main_pass.bc

out/main_pass.bc: out/program.bc
out/main_pass.bc: libencryption_pass.so
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --blue --bold --progress-dir=/home/kali/Desktop/maldev/metamorphism_sample_structure/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Running the encryption_pass on LLVM bitcode"
	/usr/lib/llvm-16/bin/opt -load-pass-plugin=/home/kali/Desktop/maldev/metamorphism_sample_structure/build/libencryption_pass.so -p encryption-pass -o /home/kali/Desktop/maldev/metamorphism_sample_structure/build/out/main_pass.bc /home/kali/Desktop/maldev/metamorphism_sample_structure/build/out/program.bc 2>&1 | tee /home/kali/Desktop/maldev/metamorphism_sample_structure/build/out/pass_output.txt

out/pass_output.txt: out/main_pass.bc
	@$(CMAKE_COMMAND) -E touch_nocreate out/pass_output.txt

out/program.bc: out/c2_handler.bc
out/program.bc: out/control_flow_handler.bc
out/program.bc: out/cryptor.bc
out/program.bc: out/instruction_substitutor.bc
out/program.bc: out/main.bc
out/program.bc: out/adjacency_table.bc
out/program.bc: out/config.bc
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --blue --bold --progress-dir=/home/kali/Desktop/maldev/metamorphism_sample_structure/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Linking LLVM bitcode files"
	/usr/lib/llvm-16/bin/llvm-link -o /home/kali/Desktop/maldev/metamorphism_sample_structure/build/out/program.bc /home/kali/Desktop/maldev/metamorphism_sample_structure/build/out/c2_handler.bc /home/kali/Desktop/maldev/metamorphism_sample_structure/build/out/control_flow_handler.bc /home/kali/Desktop/maldev/metamorphism_sample_structure/build/out/cryptor.bc /home/kali/Desktop/maldev/metamorphism_sample_structure/build/out/instruction_substitutor.bc /home/kali/Desktop/maldev/metamorphism_sample_structure/build/out/main.bc /home/kali/Desktop/maldev/metamorphism_sample_structure/build/out/adjacency_table.bc /home/kali/Desktop/maldev/metamorphism_sample_structure/build/out/config.bc

out/adjacency_table.bc: /home/kali/Desktop/maldev/metamorphism_sample_structure/src/data/adjacency_table.c
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --blue --bold --progress-dir=/home/kali/Desktop/maldev/metamorphism_sample_structure/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Generating LLVM bitcode for /home/kali/Desktop/maldev/metamorphism_sample_structure/src/data/adjacency_table.c"
	clang -c -emit-llvm --target=x86_64-w64-mingw32 -I/usr/x86_64-w64-mingw32/include/ /home/kali/Desktop/maldev/metamorphism_sample_structure/src/data/adjacency_table.c -o /home/kali/Desktop/maldev/metamorphism_sample_structure/build/out/adjacency_table.bc

out/c2_handler.bc: /home/kali/Desktop/maldev/metamorphism_sample_structure/src/core/c2_handler.c
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --blue --bold --progress-dir=/home/kali/Desktop/maldev/metamorphism_sample_structure/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Generating LLVM bitcode for /home/kali/Desktop/maldev/metamorphism_sample_structure/src/core/c2_handler.c"
	clang -c -emit-llvm --target=x86_64-w64-mingw32 -I/usr/x86_64-w64-mingw32/include/ /home/kali/Desktop/maldev/metamorphism_sample_structure/src/core/c2_handler.c -o /home/kali/Desktop/maldev/metamorphism_sample_structure/build/out/c2_handler.bc

out/config.bc: /home/kali/Desktop/maldev/metamorphism_sample_structure/src/data/config.c
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --blue --bold --progress-dir=/home/kali/Desktop/maldev/metamorphism_sample_structure/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_6) "Generating LLVM bitcode for /home/kali/Desktop/maldev/metamorphism_sample_structure/src/data/config.c"
	clang -c -emit-llvm --target=x86_64-w64-mingw32 -I/usr/x86_64-w64-mingw32/include/ /home/kali/Desktop/maldev/metamorphism_sample_structure/src/data/config.c -o /home/kali/Desktop/maldev/metamorphism_sample_structure/build/out/config.bc

out/control_flow_handler.bc: /home/kali/Desktop/maldev/metamorphism_sample_structure/src/core/control_flow_handler.c
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --blue --bold --progress-dir=/home/kali/Desktop/maldev/metamorphism_sample_structure/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_7) "Generating LLVM bitcode for /home/kali/Desktop/maldev/metamorphism_sample_structure/src/core/control_flow_handler.c"
	clang -c -emit-llvm --target=x86_64-w64-mingw32 -I/usr/x86_64-w64-mingw32/include/ /home/kali/Desktop/maldev/metamorphism_sample_structure/src/core/control_flow_handler.c -o /home/kali/Desktop/maldev/metamorphism_sample_structure/build/out/control_flow_handler.bc

out/cryptor.bc: /home/kali/Desktop/maldev/metamorphism_sample_structure/src/core/cryptor.c
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --blue --bold --progress-dir=/home/kali/Desktop/maldev/metamorphism_sample_structure/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_8) "Generating LLVM bitcode for /home/kali/Desktop/maldev/metamorphism_sample_structure/src/core/cryptor.c"
	clang -c -emit-llvm --target=x86_64-w64-mingw32 -I/usr/x86_64-w64-mingw32/include/ /home/kali/Desktop/maldev/metamorphism_sample_structure/src/core/cryptor.c -o /home/kali/Desktop/maldev/metamorphism_sample_structure/build/out/cryptor.bc

out/instruction_substitutor.bc: /home/kali/Desktop/maldev/metamorphism_sample_structure/src/core/instruction_substitutor.c
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --blue --bold --progress-dir=/home/kali/Desktop/maldev/metamorphism_sample_structure/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_9) "Generating LLVM bitcode for /home/kali/Desktop/maldev/metamorphism_sample_structure/src/core/instruction_substitutor.c"
	clang -c -emit-llvm --target=x86_64-w64-mingw32 -I/usr/x86_64-w64-mingw32/include/ /home/kali/Desktop/maldev/metamorphism_sample_structure/src/core/instruction_substitutor.c -o /home/kali/Desktop/maldev/metamorphism_sample_structure/build/out/instruction_substitutor.bc

out/main.bc: /home/kali/Desktop/maldev/metamorphism_sample_structure/src/core/main.c
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --blue --bold --progress-dir=/home/kali/Desktop/maldev/metamorphism_sample_structure/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_10) "Generating LLVM bitcode for /home/kali/Desktop/maldev/metamorphism_sample_structure/src/core/main.c"
	clang -c -emit-llvm --target=x86_64-w64-mingw32 -I/usr/x86_64-w64-mingw32/include/ /home/kali/Desktop/maldev/metamorphism_sample_structure/src/core/main.c -o /home/kali/Desktop/maldev/metamorphism_sample_structure/build/out/main.bc

executable: CMakeFiles/executable
executable: out/adjacency_table.bc
executable: out/c2_handler.bc
executable: out/config.bc
executable: out/control_flow_handler.bc
executable: out/cryptor.bc
executable: out/instruction_substitutor.bc
executable: out/main.bc
executable: out/main_pass.bc
executable: out/metamorphic.exe
executable: out/pass_output.txt
executable: out/program.bc
executable: CMakeFiles/executable.dir/build.make
.PHONY : executable

# Rule to build all files generated by this target.
CMakeFiles/executable.dir/build: executable
.PHONY : CMakeFiles/executable.dir/build

CMakeFiles/executable.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/executable.dir/cmake_clean.cmake
.PHONY : CMakeFiles/executable.dir/clean

CMakeFiles/executable.dir/depend:
	cd /home/kali/Desktop/maldev/metamorphism_sample_structure/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/kali/Desktop/maldev/metamorphism_sample_structure /home/kali/Desktop/maldev/metamorphism_sample_structure /home/kali/Desktop/maldev/metamorphism_sample_structure/build /home/kali/Desktop/maldev/metamorphism_sample_structure/build /home/kali/Desktop/maldev/metamorphism_sample_structure/build/CMakeFiles/executable.dir/DependInfo.cmake "--color=$(COLOR)"
.PHONY : CMakeFiles/executable.dir/depend

