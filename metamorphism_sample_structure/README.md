the control flow spidering might not seem very practical, but im honestly just trying to make it as difficult as possible to understand what is going on \
rest is coming at a later date unless i get bombarded by uni work again \
\
obfuscation_pass is planned \
encryption_pass is currently used to write metadata (not yet implemented, just another idea) for the post build program function_encrypter to do as the name implies using said metadata. this way i can annotate the functions i want to encrypt and have a seamless programming experience \
i just realized, that i have PIC enabled, so i don't have to worry about relocation for 99% of cases, and as long as i don't do anything stupid i won't have to manually configure the .reloc \
i just finished doing just that. like the line right above this \
things to do: \
- add function_encrypter to build pipeline for initial encryption \
- decrypting of functions during runtime \
- dynamic recrypting of functions and writing to disk (arguably the most difficult step from this list, since i need to write another rva to physical parser, but i already have code snippets this time and won't use the llvm library... probably) \
- generating and processing of metadata between function_encrypter.cpp and encryption_pass.cpp (metadata also has to include the custom key for aes) \
- implementing aes encryption inside aes.c or currently aes.h \
- cleanup of the code in function_encrypter \
also don't ask me why the program doesn't crash atm... i know why, but i think it would be funny if it did... since i'm currently calling encrypted functions