all of this raises a lot of flags for edrs, so im not sure of how to evaluate the practicality for now. \
this is currently fully functional. just a proof of concept with a few parts missing, but nontheless what i originally planned \
rest is coming at a later date since i am getting bombarded by uni work again \
\
obfuscation_pass is planned \
encryption_pass is currently used to write metadata for the post build program function_encrypter to do as the name implies using said metadata. this way i can annotate the functions i want to encrypt and have a seamless programming experience \
things to do for now (in order):
- function_encrypter.cpp needs to calculate the stripped and unstripped offsets of my functions and the .meta section so i don't have to use a magic number offset in source. this also needs to be included in the .bin i write to the section
- cleanup of the code base
- encryption of the meta_engine.exe
- implementing aes encryption inside aes.c or currently aes.h
- not really sure how i can reincrypt with aes without having to load everything into memory, decrypting and then reincrypting
- very unspecific, but fill in the missing c2 components and weaponize the core structure (i have no interest in actually weaponizing it, just make it somewhat realistic or useful)
\
with my currently limited understanding the loader is neccessary, since i cannot just unmap the .text section without consequences for recryption or other meta_engine tasks \
