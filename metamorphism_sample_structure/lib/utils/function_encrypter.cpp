// To be run on the outputted Object file during compilation

#include "llvm/Object/ObjectFile.h"
#include "llvm/Object/SymbolSize.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Support/InitLLVM.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/Object/COFF.h"

#include <llvm/Support/Error.h>
#include <llvm/Support/MemoryBuffer.h>
#include <llvm/ADT/StringRef.h>

#include <algorithm>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>

using namespace llvm;
using namespace llvm::object;



uint64_t getPEBaseAddress(const COFFObjectFile *PEObj) {
    // Get the ImageBase from the Optional Header
    outs() << "PE Base Address: 0x" << Twine::utohexstr(PEObj->getImageBase()) << "\n";
    return PEObj->getImageBase();

}

uint64_t getTextSectionAddress(const COFFObjectFile *PEObj) {
    uint64_t textBaseAddress = 0;
    for (const SectionRef &Section : PEObj->sections()) {
        Expected<StringRef> SectionNameOrErr = Section.getName();
        if (!SectionNameOrErr) {
            errs() << "Error: " << toString(SectionNameOrErr.takeError()) << "\n";
            continue;
        }

        StringRef SectionName = *SectionNameOrErr;
        if (SectionName == ".text") {
            textBaseAddress = Section.getAddress();
            outs() << "Text Section Base Address: 0x" << Twine::utohexstr(textBaseAddress) << "\n";
            break;
        }
    }
    return textBaseAddress;
}

uint64_t getTextSectionSize(const COFFObjectFile *PEObj) {
    uint64_t textSectionSize = 0;
    for (const SectionRef &Section : PEObj->sections()) {
        Expected<StringRef> SectionNameOrErr = Section.getName();
        if (!SectionNameOrErr) {
            errs() << "Error: " << toString(SectionNameOrErr.takeError()) << "\n";
            continue;
        }

        StringRef SectionName = *SectionNameOrErr;
        if (SectionName == ".text") {
            textSectionSize = Section.getSize();
            outs() << "Text Section Size: " << textSectionSize << "\n";
            break;
        }
    }
    return textSectionSize;  
}

struct FunctionInfo {
    uint64_t physicalAddress;
    uint64_t size;
    StringRef name;

    FunctionInfo(uint64_t addr, uint64_t sz, StringRef n) : physicalAddress(addr), size(sz), name(n) {}
};

uint64_t rva2offset(const COFFObjectFile *PEObj, uint64_t RVA) {
    // Iterate through the sections and find the .text section
    for (const SectionRef &Section : PEObj->sections()) {
        Expected<StringRef> SectionNameOrErr = Section.getName();
        if (!SectionNameOrErr) {
            errs() << "Error: " << toString(SectionNameOrErr.takeError()) << "\n";
            continue;
        }

        StringRef SectionName = *SectionNameOrErr;

        // Check if the section is .text
        if (SectionName == ".text") {
            // Retrieve section's base address and size
            uint64_t sectionBaseAddress = Section.getAddress();
            uint64_t sectionSize = Section.getSize();

            // Get the corresponding COFF section using the SectionRef directly
            Expected<const coff_section*> SectionOrErr = PEObj->getCOFFSection(Section);
            if (!SectionOrErr) {
                errs() << "Error: " << toString(SectionOrErr.takeError()) << "\n";
                continue;  // Skip if an error occurs
            }

            const coff_section* CoffSection = *SectionOrErr;

            // Compare section name with the one from COFF section (use StringRef for comparison)
            if (SectionName == StringRef(CoffSection->Name)) {
                // We found the matching section, now get PointerToRawData
                uint64_t pointerToRawData = CoffSection->PointerToRawData;

                // Check if the RVA is within the .text section's address range
                if (RVA >= sectionBaseAddress && RVA < sectionBaseAddress + sectionSize) {
                    // Calculate the offset using PointerToRawData
                    uint64_t offset = RVA - sectionBaseAddress + pointerToRawData;

                    return offset;
                }
            }
        }
    }

    // If we reach here, the RVA was not found in the .text section
    errs() << "Error: RVA 0x" << Twine::utohexstr(RVA) << " not found in the .text section.\n";
    return UINT64_MAX;  // Return an invalid offset if not found
}

std::vector<FunctionInfo> analyzeExecutable(StringRef FilePath) {
    std::vector<FunctionInfo> functionsData;

    Expected<OwningBinary<Binary>> BinaryOrErr = createBinary(FilePath);
    if (!BinaryOrErr) {
        errs() << "Error: " << toString(BinaryOrErr.takeError()) << "\n";
        return functionsData;
    }

    Binary &Binary = *BinaryOrErr.get().getBinary();

    uint64_t baseAddress = 0;
    uint64_t textBaseAddress = 0;
    uint64_t textSectionSize = 0;
    const COFFObjectFile *PEObj = nullptr;

    // Check if the binary is a PE file
    if (const COFFObjectFile *TempPEObj = dyn_cast<COFFObjectFile>(&Binary)) {
        PEObj = TempPEObj;  // Store the PEObjectFile reference
        baseAddress = getPEBaseAddress(PEObj);
        textBaseAddress = getTextSectionAddress(PEObj);
        textSectionSize = getTextSectionSize(PEObj);
        if (textBaseAddress == 0) {
            errs() << "Error: .text section not found!\n";
            return functionsData;
        }
    } else {
        errs() << "Error: Not a PE binary!\n";
        return functionsData;
    }

    if (ObjectFile *Obj = dyn_cast<ObjectFile>(&Binary)) {
        SmallVector<FunctionInfo, 64> allFunctions; // Store all functions (unfiltered)

        // Collect all functions
        for (const SymbolRef &Symbol : Obj->symbols()) {
            Expected<uint64_t> AddressOrErr = Symbol.getAddress();
            if (!AddressOrErr) {
                errs() << "Error: " << toString(AddressOrErr.takeError()) << "\n";
                continue;
            }

            uint64_t Address = *AddressOrErr;

            // Check if the symbol's address is within the .text section (now using physical address)
            if (Address >= textBaseAddress && Address < textBaseAddress + textSectionSize) {
                Expected<StringRef> NameOrErr = Symbol.getName();
                if (!NameOrErr) {
                    errs() << "Error: " << toString(NameOrErr.takeError()) << "\n";
                    continue;
                }

                StringRef Name = *NameOrErr;

                // Convert RVA to physical address using rva2offset
                uint64_t offset = rva2offset(PEObj, Address);
                if (offset == UINT64_MAX) {
                    Expected<StringRef> NameOrErr = Symbol.getName();
                    if (!NameOrErr) {
                        errs() << "Error: Unable to get symbol name: " << toString(NameOrErr.takeError()) << "\n";
                    } else {
                        errs() << "Error: Unable to translate RVA to offset for symbol: " << *NameOrErr << "\n";
                    }
                    continue;
                }

                // Add the function to the list with its translated address
                allFunctions.push_back(FunctionInfo(offset, 0, Name));
            }
        }

        // Sort all functions by address
        std::sort(allFunctions.begin(), allFunctions.end(),
                  [](const FunctionInfo &a, const FunctionInfo &b) {
                      return a.physicalAddress < b.physicalAddress;
                  });

        // Calculate function sizes relative to the next function or section
        for (size_t i = 0; i < allFunctions.size(); ++i) {
            uint64_t nextBoundary = 0;

            // Find the next function or section boundary
            if (i + 1 < allFunctions.size()) {
                nextBoundary = allFunctions[i + 1].physicalAddress;
            } else {
                // For the last function, find the end of the .text section
                nextBoundary = textBaseAddress + textSectionSize;
            }

            // Check if the next boundary is valid and calculate the size
            if (nextBoundary > allFunctions[i].physicalAddress) {
                allFunctions[i].size = nextBoundary - allFunctions[i].physicalAddress;
            }
            else {
                // If there's an issue with the size, set it to 0
                allFunctions[i].size = 0;
            }
        }

        // Apply the filter and store the filtered functions
        for (const auto &func : allFunctions) {
            if (func.name.contains("node")) { // Apply the filter here
                functionsData.push_back(func);
            }
        }

        // Debug output for the filtered functions
        for (const auto &func : functionsData) {
            outs() << "Function: " << func.name
                   << " Address: 0x" << Twine::utohexstr(func.physicalAddress)
                   << " Size: " << func.size << " bytes\n";
        }
    }

    return functionsData;
}

void xorEncryptFunctions(std::vector<FunctionInfo>& functionsData, uint64_t binaryBaseAddress, uint8_t key, std::vector<char>& buffer) {
    for (auto& func : functionsData) {
        // Adjust the address
        uint64_t adjustedAddress = binaryBaseAddress + func.physicalAddress;

        // Encrypt the function bytes using XOR
        uint64_t offset = adjustedAddress - binaryBaseAddress;
        for (uint64_t i = offset; i < offset + func.size; ++i) {
            buffer[i] ^= key;
        }
    }
}

// XOR encryption function for the binary
void xorEncryptBinary(const std::string& filePath, uint8_t key) {
    // Step 1: Read the binary file into memory
    std::ifstream inputFile(filePath, std::ios::binary | std::ios::ate);
    if (!inputFile.is_open()) {
        std::cerr << "Error: Could not open file " << filePath << "\n";
        return;
    }

    // Read the file into a memory buffer
    std::streamsize size = inputFile.tellg();
    inputFile.seekg(0, std::ios::beg);
    
    std::vector<char> buffer(size);
    if (!inputFile.read(buffer.data(), size)) {
        std::cerr << "Error: Could not read the file " << filePath << "\n";
        return;
    }
    inputFile.close();

    // Step 2: Analyze the executable to get function data
    StringRef filePathRef(filePath);
    std::vector<FunctionInfo> functionsData = analyzeExecutable(filePathRef);

    // Step 3: Get the actual memory address of the buffer as the binaryBaseAddress
    uint64_t binaryBaseAddress = reinterpret_cast<uint64_t>(buffer.data());
    std::cout << "Loaded binary in memory at address: 0x" << std::hex << binaryBaseAddress << "\n";

    // Step 4: Encrypt the functions using XOR
    xorEncryptFunctions(functionsData, binaryBaseAddress, key, buffer);

    // Step 5: Write the modified binary back to disk
    std::ofstream outputFile(filePath + "_encrypted.exe", std::ios::binary);
    if (!outputFile.is_open()) {
        std::cerr << "Error: Could not open file for writing " << filePath << "\n";
        return;
    }

    outputFile.write(buffer.data(), size);
    outputFile.close();

    std::cout << "Encryption complete. File has been modified: " << filePath + "_encrypted.exe" << "\n";
}

int main(int argc, char **argv) {
    InitLLVM X(argc, argv);

    if (argc < 2) {
        errs() << "Usage: " << argv[0] << " <binary-file>\n";
        return 1;
    }

    const uint8_t XOR_KEY = 0xAA;  // Example static key, modify as needed

    // Call the function to XOR encrypt the binary and overwrite the original
    xorEncryptBinary(argv[1], XOR_KEY);

    return 0;
}
