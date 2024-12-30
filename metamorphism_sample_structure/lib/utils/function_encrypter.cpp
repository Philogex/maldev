// To be run on the outputted Object file during compilation

#include "llvm/Object/ObjectFile.h"
#include "llvm/Object/SymbolSize.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Support/InitLLVM.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/ADT/SmallVector.h"
#include <algorithm>
#include <iostream>
#include <vector>

using namespace llvm;
using namespace llvm::object;

struct FunctionSymbol {
    uint64_t address;
    StringRef name;

    FunctionSymbol(uint64_t addr, StringRef n) : address(addr), name(n) {}
};


void analyzeExecutable(StringRef FilePath) {
    Expected<OwningBinary<Binary>> BinaryOrErr = createBinary(FilePath);
    if (!BinaryOrErr) {
        errs() << "Error: " << toString(BinaryOrErr.takeError()) << "\n";
        return;
    }

    Binary &Binary = *BinaryOrErr.get().getBinary();
    if (ObjectFile *Obj = dyn_cast<ObjectFile>(&Binary)) {
        SmallVector<FunctionSymbol, 64> FunctionSymbols;

        // Extract symbols from the object file
        for (const SymbolRef &Symbol : Obj->symbols()) {
            Expected<uint64_t> AddressOrErr = Symbol.getAddress();
            if (!AddressOrErr) {
                errs() << "Error: " << toString(AddressOrErr.takeError()) << "\n";
                continue;
            }

            uint64_t Address = *AddressOrErr;

            Expected<StringRef> NameOrErr = Symbol.getName();
            if (!NameOrErr) {
                errs() << "Error: " << toString(NameOrErr.takeError()) << "\n";
                continue;
            }

            StringRef Name = *NameOrErr;

            // Store the symbol address and name in the vector
            FunctionSymbols.push_back(FunctionSymbol(Address, Name));
        }

        // Sort symbols by address
        std::sort(FunctionSymbols.begin(), FunctionSymbols.end(),
                  [](const FunctionSymbol &a, const FunctionSymbol &b) {
                      return a.address < b.address;
                  });

        // Print out function sizes
        for (size_t i = 0; i < FunctionSymbols.size() - 1; ++i) {
            uint64_t func_size = FunctionSymbols[i + 1].address - FunctionSymbols[i].address;
            outs() << "Function: " << FunctionSymbols[i].name
                   << " Address: " << FunctionSymbols[i].address
                   << " Size: " << func_size << " bytes\n";
        }

        // Handle the last function: find the end of the section it's in
        const SectionRef *lastSection = nullptr;
        for (const SectionRef &Section : Obj->sections()) {
            Expected<StringRef> SectionNameOrErr = Section.getName();  // Get Expected<StringRef>
            if (!SectionNameOrErr) {
                errs() << "Error: " << toString(SectionNameOrErr.takeError()) << "\n";
                continue;
            }
            StringRef SectionName = *SectionNameOrErr;  // Unwrap Expected<StringRef>

            if (SectionName == ".text") {
                lastSection = &Section;
                break;
            }
        }

        if (lastSection) {
            uint64_t section_end = lastSection->getAddress() + lastSection->getSize();
            uint64_t last_func_size = section_end - FunctionSymbols.back().address;
            outs() << "Function: " << FunctionSymbols.back().name
                   << " Address: " << FunctionSymbols.back().address
                   << " Size: " << last_func_size << " bytes\n";
        }
    }
}



int main(int argc, char **argv) {
    InitLLVM X(argc, argv);

    if (argc < 2) {
        errs() << "Usage: " << argv[0] << " <binary-file>\n";
        return 1;
    }

    analyzeExecutable(argv[1]);
    return 0;
}
