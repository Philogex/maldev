// To be run on the outputted Object file during compilation

#include "llvm/Object/ObjectFile.h"
#include "llvm/Object/SymbolSize.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Support/InitLLVM.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/Object/COFF.h"
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

uint64_t getPEBaseAddress(const COFFObjectFile *PEObj) {
    // Get the ImageBase from the Optional Header
    return PEObj->getImageBase();
}

void analyzeExecutable(StringRef FilePath) {
    Expected<OwningBinary<Binary>> BinaryOrErr = createBinary(FilePath);
    if (!BinaryOrErr) {
        errs() << "Error: " << toString(BinaryOrErr.takeError()) << "\n";
        return;
    }

    Binary &Binary = *BinaryOrErr.get().getBinary();

    // following two are unused, but might be helpful later on
    uint64_t baseAddress = 0;
    uint64_t textBaseAddress = 0;

    // Check if the binary is a PE file
    if (const COFFObjectFile *PEObj = dyn_cast<COFFObjectFile>(&Binary)) {
        baseAddress = getPEBaseAddress(PEObj);
        // Iterate over all sections in the PE file
        for (const SectionRef &Section : PEObj->sections()) {
            Expected<StringRef> SectionNameOrErr = Section.getName();  // Get section name
            if (!SectionNameOrErr) {
                errs() << "Error: " << toString(SectionNameOrErr.takeError()) << "\n";
                continue;
            }

            StringRef SectionName = *SectionNameOrErr;

            // Check if the section is the .text section (which contains the executable code)
            if (SectionName == ".text") {
                // Get the base address of the .text section
                textBaseAddress = Section.getAddress();
                outs() << "Text Section Base Address: 0x" << Twine::utohexstr(textBaseAddress) << "\n";
                break;  // No need to continue after finding the .text section
            }
        }

        // If we didn't find the .text section, print an error
        if (textBaseAddress == 0) {
            errs() << "Error: .text section not found!\n";
        }
    } else {
        errs() << "Error: Not a PE binary!\n";
    }

    if (ObjectFile *Obj = dyn_cast<ObjectFile>(&Binary)) {
        SmallVector<FunctionSymbol, 64> FunctionSymbols;

        // Extract symbols from the object file
        /* unused again, but might be helpful later. this will get replaced by metadata search anyways, so no need to implement
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

            // Filter out symbols
            if (!Name.contains("node")) {
                continue;
            }

            FunctionSymbols.push_back(FunctionSymbol(Address, Name));
        }
        */

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
                   << " Address: " << Twine::utohexstr(FunctionSymbols[i].address)
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
