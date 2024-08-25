# This throws a lot of errors, and i don't know if i should be concerned or not
# Following was taken from https://blog.scrt.ch/2020/06/19/engineering-antivirus-evasion/ and modified, but they had used very old syntax, since the article is from 2020

# WIN_INCLUDE="/usr/lib/gcc/x86_64-w64-mingw32/13-win32"
# CLANG_PATH="/usr/lib/llvm-16"

# clang++ -cc1 -ast-dump "$1" -D "_WIN64" -D "_UNICODE" -D "UNICODE" -D "_WINSOCK_DEPRECATED_NO_WARNINGS"\
#  "-I" "$CLANG_PATH/include/llvm/" \
#  "-I" "$CLANG_PATH/lib/clang/16/include/" \
#  "-I" "/usr/x86_64-w64-mingw32/include/" \
#  "-I" "$CLANG_PATH" \
#  "-I" "$WIN_INCLUDE" \
#  "-I" "$WIN_INCLUDE/include/" \
#  "-I" "$WIN_INCLUDE/include/c++/" \
#  "-I" "$WIN_INCLUDE/include/c++/x86_64-w64-mingw32/" \
#  "-I" "$WIN_INCLUDE/include/c++/tr1/" \
#  "-fdeprecated-macro" \
#  "-w" \
#  "-fdebug-compilation-dir"\
#  "-fno-use-cxa-atexit" "-fms-extensions" "-fms-compatibility" \
#  "-std=c++17" "-fdelayed-template-parsing" "-fobjc-runtime=gcc" "-fcxx-exceptions" "-fexceptions" "-fcolor-diagnostics" "-x" "c++"



# This should work... (it does not work)
# clang++ -Wno-unused-command-line-argument --target=x86_64-w64-mingw32 -I/usr/lib/gcc/x86_64-w64-mingw32/13-win32/include/c++/x86_64-w64-mingw32/ -I/usr/lib/gcc/x86_64-w64-mingw32/13-win32/include/c++/ -L/usr/lib/gcc/x86_64-w64-mingw32/13-win32/ -static-libgcc -static-libstdc++ -o out/win64_llvm src/main.cpp
clang++ -E --target=x86_64-w64-mingw32 -I/usr/lib/gcc/x86_64-w64-mingw32/13-win32/include/c++/x86_64-w64-mingw32/ -I/usr/lib/gcc/x86_64-w64-mingw32/13-win32/include/c++/ "$1" -o out/preprocessed_main.cpp

# I hate it here
# /nologo /utf-8 /EHsc /GR /permissive- /std:c++20 /Zc:__cplusplus /Zc:externC- /W4 /wd4459 /D _CRT_SECURE_NO_WARNINGS=1 /D _STL_SECURE_NO_WARNINGS=1
# clang++ --target=x86_64-w64-mingw32 -Xclang -ast-dump -L/usr/lib/gcc/x86_64-w64-mingw32/13-win32/  -v out/preprocessed_main.cpp

# I will not continue this for the moment, since i will follow my original plan to modify the IR
# The idea to modify the AST also isn't completely irrelevant or undoable, since i just can't dump the AST, but that doesn't mean i can't modify it using clangs AST Interface