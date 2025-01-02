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
#include <sstream>
#include <vector>
#include <cstring>
#include <string>
#include <iomanip>

using namespace llvm;
using namespace llvm::object;

struct FunctionInfo {
    uint64_t virtualAddress;
    uint64_t physicalAddress;
    uint64_t size;
    char name[64];  // Fixed-size array for C compatibility

    FunctionInfo(uint64_t addr1, uint64_t addr2, uint64_t sz, const char* n) : virtualAddress(addr1), physicalAddress(addr2), size(sz) {
        strncpy(name, n, sizeof(name) - 1);
        name[sizeof(name) - 1] = '\0';  // Ensure null termination
    }
};

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
            outs() << ".text Section Base Address: 0x" << Twine::utohexstr(textBaseAddress) << "\n";
            break;
        }
    }
    return textBaseAddress;
}

uint64_t getMetaSectionAddress(const COFFObjectFile *PEObj) {
    uint64_t textBaseAddress = 0;
    for (const SectionRef &Section : PEObj->sections()) {
        Expected<StringRef> SectionNameOrErr = Section.getName();
        if (!SectionNameOrErr) {
            errs() << "Error: " << toString(SectionNameOrErr.takeError()) << "\n";
            continue;
        }

        StringRef SectionName = *SectionNameOrErr;
        if (SectionName == ".meta") {
            textBaseAddress = Section.getAddress();
            outs() << ".meta Section Base Address: 0x" << Twine::utohexstr(textBaseAddress) << "\n";
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
            outs() << "Text Section Size: 0x" << textSectionSize << "\n";
            break;
        }
    }
    return textSectionSize;  
}

uint64_t rva2offset(const COFFObjectFile *PEObj, uint64_t RVA) {
    // Iterate through the sections and find the .text section
    for (const SectionRef &Section : PEObj->sections()) {
        Expected<StringRef> SectionNameOrErr = Section.getName();
        if (!SectionNameOrErr) {
            errs() << "Error: " << toString(SectionNameOrErr.takeError()) << "\n";
            continue;
        }

        StringRef SectionName = *SectionNameOrErr;
        
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

    // If we reach here, the RVA was not found in the .text section
    errs() << "Error: RVA 0x" << Twine::utohexstr(RVA) << " not found in the .text section.\n";
    return UINT64_MAX;  // Return an invalid offset if not found
}

std::vector<std::string> deserializeAnnotatedFunctions(const std::string &filePath) {
    std::vector<std::string> functionNames;

    std::ifstream inFile(filePath, std::ios::binary);
    if (!inFile) {
        errs() << "Error: Unable to open file: " << filePath << "\n";
        return functionNames;
    }

    // Read the size of the array (8 bytes)
    uint64_t arraySize = 0;
    inFile.read(reinterpret_cast<char *>(&arraySize), sizeof(arraySize));
    if (!inFile) {
        errs() << "Error: Failed to read array size from file\n";
        return functionNames;
    }

    if(arraySize == 0) {
        errs() << "No function to be encrypted. Exiting\n";
        exit(0);
    }

    // Read each function name (64 bytes per entry)
    for (uint64_t i = 0; i < arraySize; ++i) {
        char nameBuffer[64] = {0};
        inFile.read(nameBuffer, sizeof(nameBuffer));
        if (!inFile) {
            errs() << "Error: Failed to read function name from file\n";
            break;
        }

        // Convert to std::string and add to the vector
        functionNames.emplace_back(nameBuffer);
    }

    inFile.close();
    return functionNames;
}

// VERY IMPORTANT: to generate less telemetry this should fuse directly adjacent functions
std::vector<FunctionInfo> analyzeExecutable(StringRef FilePath) {
    std::vector<FunctionInfo> functionsData;

    // Deserialize annotated functions
    const std::string annotationsFile = "annotated_functions.bin";
    std::vector<std::string> annotatedFunctions = deserializeAnnotatedFunctions(annotationsFile);

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
                allFunctions.push_back(FunctionInfo(Address - baseAddress, offset, 0, Name.str().c_str()));
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

        // Filter functions (example: only those containing "node")
        for (const auto &func : allFunctions) {
            for (const auto &annotatedFunc : annotatedFunctions) {
                if (std::strcmp(func.name, annotatedFunc.c_str()) == 0) {
                    functionsData.push_back(func);
                    break; // Stop searching after finding a match
                }
            }
        }

        // Debug output for the filtered functions
        for (const auto &func : functionsData) {
            outs() << "Function: " << func.name
                   << " virtual Address: 0x" << Twine::utohexstr(func.virtualAddress)
                   << " physical Address: 0x" << Twine::utohexstr(func.physicalAddress)
                   << " Size: " << func.size << " bytes\n";
        }
    }

    return functionsData;
}

void xorEncryptFunctions(std::vector<FunctionInfo>& functionsData, uint8_t key, std::vector<char>& buffer) {
    uint64_t binaryBaseAddress = reinterpret_cast<uint64_t>(buffer.data());
    // outs() << "binaryBaseAddress: 0x" << Twine::utohexstr(binaryBaseAddress) << "\n";
    for (auto& func : functionsData) {
        // Calculate the correct offset for the function in the buffer
        uint64_t functionStartOffset = func.physicalAddress;
        
        // outs() << "functionStartOffset: 0x" << Twine::utohexstr(functionStartOffset) << "\n"; 

        uint64_t functionEndOffset = functionStartOffset + func.size;

        // Encrypt the function bytes using XOR
        for (uint64_t i = functionStartOffset; i < functionEndOffset; ++i) {
            buffer[i] ^= key;
        }
    }
}

void xorEncryptBinary(const std::string& filePath, uint8_t key, std::vector<FunctionInfo>& functionsData) {
    // Step 1: Read the binary file into a buffer
    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        std::cerr << "Error opening file: " << filePath << std::endl;
        return;
    }

    std::vector<char> buffer((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();

    // Step 3: Apply XOR encryption to the specified functions
    xorEncryptFunctions(functionsData, key, buffer);

    // Step 4: Write the encrypted buffer back to the file
    std::ofstream outFile(filePath, std::ios::binary);
    if (!outFile) {
        std::cerr << "Error opening output file: " << filePath << std::endl;
        return;
    }

    outFile.write(buffer.data(), buffer.size());
    outFile.close();

    std::cout << "Binary encrypted successfully!" << std::endl;
}


std::vector<char> serializeFunctionData(const std::vector<FunctionInfo>& functions) {
    std::vector<char> serializedData;

    // Serialize each FunctionInfo
    for (const auto& func : functions) {
        // Serialize the virtual address (8 bytes)
        for (int i = 0; i < 8; ++i) {
            serializedData.push_back(static_cast<char>((func.virtualAddress >> (i * 8)) & 0xFF));
        }
        // Serialize the physical address (8 bytes)
        for (int i = 0; i < 8; ++i) {
            serializedData.push_back(static_cast<char>((func.physicalAddress >> (i * 8)) & 0xFF));
        }
        // Serialize the size (8 bytes)
        for (int i = 0; i < 8; ++i) {
            serializedData.push_back(static_cast<char>((func.size >> (i * 8)) & 0xFF));
        }
        // Serialize the name (256 bytes, fixed size)
        for (int i = 0; i < 64; ++i) {
            serializedData.push_back(func.name[i]);
        }
    }

    return serializedData;
}

Expected<std::unique_ptr<COFFObjectFile>> readCOFFObjectFile(const std::string &filePath) {
    ErrorOr<std::unique_ptr<MemoryBuffer>> bufferOrErr = MemoryBuffer::getFile(filePath);
    if (std::error_code ec = bufferOrErr.getError()) {
        return createStringError(ec, "Failed to open file: " + filePath);
    }

    Expected<std::unique_ptr<COFFObjectFile>> objOrErr = ObjectFile::createCOFFObjectFile(*bufferOrErr.get());
    if (!objOrErr) {
        return objOrErr.takeError();
    }

    return objOrErr;
}

void writeSerializedDataToExecutable(const std::string& filePath, const std::vector<FunctionInfo>& functionsData) {
    std::vector<char> serializedData = serializeFunctionData(functionsData);

    Expected<OwningBinary<Binary>> BinaryOrErr = createBinary(filePath);
    if (!BinaryOrErr) {
        errs() << "Error: " << toString(BinaryOrErr.takeError()) << "\n";
        return;
    }

    Binary &Binary = *BinaryOrErr.get().getBinary();
    
    const COFFObjectFile *PEObj = nullptr;

    // Check if the binary is a PE file
    if (const COFFObjectFile *TempPEObj = dyn_cast<COFFObjectFile>(&Binary)) {
        PEObj = TempPEObj;
    } else {
        errs() << "Not a valid PE file.\n";
        return;
    }

    uint64_t metaSectionOffset = rva2offset(PEObj, getMetaSectionAddress(PEObj));

    std::cout << ".meta Offset: 0x" << std::hex << metaSectionOffset << std::endl; 

    if (metaSectionOffset == 0) {
        std::cerr << "No valid metadata section found!" << std::endl;
        return;
    }

    std::fstream file(filePath, std::ios::in | std::ios::out | std::ios::binary);
    if (!file) {
        std::cerr << "Error opening file: " << filePath << std::endl;
        return;
    }

    file.seekp(metaSectionOffset);
    if (!file) {
        std::cerr << "Error seeking to the specified offset in the file." << std::endl;
        return;
    }

    std::vector<char>::size_type amount = serializedData.size() / sizeof(FunctionInfo);
    file.write(reinterpret_cast<const char*>(&amount), sizeof(amount));
    file.write(serializedData.data(), serializedData.size());

    std::cout << "Writing Data of Size: 0x" << std::hex << serializedData.size() << " to .meta" << std::endl;
    file.write(serializedData.data(), serializedData.size());
    if (!file) {
        std::cerr << "Error writing serialized data to file." << std::endl;
        return;
    }

    file.close();
    
    std::cout << "Serialized data written to executable successfully!" << std::endl;
}


int main(int argc, char** argv) {
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0] << " <input_file> <output_file> <key>" << std::endl;
        std::cerr << "Example: " << argv[0] << " input.exe output.exe 0xAA" << std::endl;
        return 1;
    }

    std::string inputFilePath = argv[1];  // Path to the existing input file
    std::string outputFilePath = argv[2];  // Path to the new output file to be created
    std::string keyStr = argv[3];  // Encryption key string
    uint8_t encryptionKey = 0;

    // Process encryption key
    if (keyStr.substr(0, 2) == "0x" || keyStr.substr(0, 2) == "0X") {
        std::stringstream ss;
        ss << std::hex << keyStr.substr(2);
        int tempKey;
        ss >> tempKey;

        if (ss.fail()) {
            std::cerr << "Error: Failed to parse the key as a hexadecimal number!" << std::endl;
            return 1;
        }
        encryptionKey = static_cast<uint8_t>(tempKey);
    } else {
        try {
            encryptionKey = std::stoi(keyStr);
        } catch (const std::invalid_argument& e) {
            std::cerr << "Error: Invalid key format!" << std::endl;
            return 1;
        }
    }

    std::cout << "Using encryption key: 0x" << std::hex << +encryptionKey << std::endl;

    // Copy the input file to the output file (1:1 copy)
    std::ifstream inputFile(inputFilePath, std::ios::binary);
    std::ofstream outputFile(outputFilePath, std::ios::binary);
    if (!inputFile) {
        std::cerr << "Error opening input file: " << inputFilePath << std::endl;
        return 1;
    }
    if (!outputFile) {
        std::cerr << "Error opening output file: " << outputFilePath << std::endl;
        return 1;
    }

    // Perform a 1:1 copy of the input file to the output file
    outputFile << inputFile.rdbuf();

    inputFile.close();
    outputFile.close();

    // Analyze functions in the input file
    std::vector<FunctionInfo> functions = analyzeExecutable(inputFilePath);
    if (functions.empty()) {
        std::cerr << "No functions found or failed to analyze executable!" << std::endl;
        return 1;
    }

    // Perform XOR encryption and write encrypted binary to the output file
    xorEncryptBinary(outputFilePath, encryptionKey, functions);  // Encrypt and write to output file

    // Write serialized data to the output executable
    writeSerializedDataToExecutable(outputFilePath, functions);  // Write to output file

    return 0;
}
