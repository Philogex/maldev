the control flow spidering might not seem very practical, but im honestly just trying to make it as difficult as possible to understand what is going on
rest is coming at a later date unless i get bombarded by uni work again

problem: i'm currently stuck at finding a good way to encrypt my nodes during compilation... i might even try using llvm jit, but that's not really valuable for malware development. just something nice to think about
solution: just implemented the first step to compiling my nodes during optimization (when my pass runs) and taking the outputted machine code and aes encrypting them and putting them into some form (arrays or just pointers to memory idk) to be executed during runtime
problem: machine code is not linked, so i will have unreferenced calls or jumps in my nodes/ functions
solution: llvm::Linker::linkModules :DDDDDDD