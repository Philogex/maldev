the control flow spidering might not seem very practical, but im honestly just trying to make it as difficult as possible to understand what is going on \
rest is coming at a later date unless i get bombarded by uni work again \
\
obfuscation_pass is planned \
encryption_pass is currently used to write metadata (not yet implemented, just another idea) for the post build program function_encrypter to do as the name implies using said metadata. this way i can annotate the functions i want to encrypt and have a seamless programming experience \
i just realized, that i have PIC enabled, so i don't have to worry about relocation for 99% of cases, and as long as i don't do anything stupid i won't have to manually configure the .reloc \
i just finished doing just that. like the line right above this \
things to do:
- dynamic recrypting of functions and writing to disk
- generating and processing of metadata between function_encrypter.cpp and encryption_pass.cpp (metadata also has to include the custom key for aes generated during compile process)
- currently looking for a way to properly set the aes key. i will probably set it at the end of my .meta section for now
- implementing aes encryption inside aes.c or currently aes.h
- not really sure how i can reincrypt with aes without having to load everything into memory, decrypting and then reincrypting

also don't ask me why the program doesn't crash atm... i know why, but i think it would be funny if it did... since i'm currently calling encrypted functions \
i added a custom section .meta for metadata / the function offsets so i can strip the binary and still find my functions\
went full circle now. (if you don't know what i mean it doesn't matter) \
i will do code cleanup after finishing the recryption of the executable, so just the pe loader and shared memory missing