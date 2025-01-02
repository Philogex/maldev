#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/TargetParser/TargetParser.h"
#include "llvm/Analysis/TargetTransformInfo.h"
#include "llvm/IR/Function.h"
#include "llvm/Target/TargetMachine.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/Support/Host.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Target/TargetOptions.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/MC/TargetRegistry.h"
#include <fstream>
#include <cstring>

using namespace llvm;

const char *AnnotationString = "encrypt";

namespace {
    void serializeFunctionNames(const std::vector<std::string> &functionNames, const std::string &outputFilePath) {
        // Open the output file
        std::ofstream outFile(outputFilePath, std::ios::binary);
        if (!outFile) {
            errs() << "Error: Unable to open output file for writing: " << outputFilePath << "\n";
            return;
        }

        // Write the number of entries in the array (8 bytes)
        uint64_t arraySize = functionNames.size();
        outFile.write(reinterpret_cast<const char *>(&arraySize), sizeof(arraySize));

        // Write each function name (64 bytes per entry)
        for (const std::string &name : functionNames) {
            char nameBuffer[64];
            std::memset(nameBuffer, 0, sizeof(nameBuffer)); // Fill with null bytes
            std::strncpy(nameBuffer, name.c_str(), sizeof(nameBuffer) - 1); // Copy name, ensuring no overflow
            outFile.write(nameBuffer, sizeof(nameBuffer)); // Write the fixed-size name entry
        }

        outFile.close();
    }

    void findAnnotatedFunctions(Module &M, const std::string &outputFilePath) {
        std::vector<std::string> annotatedFunctions;
        // Look for llvm.global.annotations
        for (GlobalVariable &GV : M.globals()) {
            if (GV.getName() == "llvm.global.annotations" && GV.hasInitializer()) {
                auto *Annotations = dyn_cast<ConstantArray>(GV.getInitializer());
                if (!Annotations) {
                    errs() << "llvm.global.annotations is not a constant array!\n";
                    continue;
                }

                // Iterate over the annotations
                for (const Use &U : Annotations->operands()) {
                    auto *AnnotationStruct = dyn_cast<ConstantStruct>(U.get());
                    if (!AnnotationStruct || AnnotationStruct->getNumOperands() < 2) {
                        errs() << "Annotation entry is invalid!\n";
                        continue;
                    }

                    // Get the annotated function
                    auto *AnnotatedFunction = dyn_cast<Function>(
                        AnnotationStruct->getOperand(0)->stripPointerCasts());
                    auto *AnnotationGV = dyn_cast<GlobalVariable>(
                        AnnotationStruct->getOperand(1)->stripPointerCasts());
                    
                    if (!AnnotatedFunction || !AnnotationGV || !AnnotationGV->hasInitializer()) {
                        errs() << "Invalid annotation structure!\n";
                        continue;
                    }

                    // Get the annotation string
                    auto *AnnotationData = dyn_cast<ConstantDataArray>(AnnotationGV->getInitializer());
                    if (AnnotationData && AnnotationData->isString()) {
                        StringRef Annotation = AnnotationData->getAsCString();
                        if (Annotation.equals(AnnotationString)) {
                            // Function matches the annotation string
                            errs() << "Found annotated function: " 
                                   << AnnotatedFunction->getName()
                                   << " with annotation: " << Annotation << "\n";
                            annotatedFunctions.push_back(AnnotatedFunction->getName().str());
                        }
                    }
                }
            }
        }
        serializeFunctionNames(annotatedFunctions, outputFilePath);
    }

    struct EncryptionPass : PassInfoMixin<EncryptionPass> {
        PreservedAnalyses run(Module &M, ModuleAnalysisManager &) {
            const std::string outputFilePath = "annotated_functions.bin";
            findAnnotatedFunctions(M, outputFilePath);

            return PreservedAnalyses::all();
        }

        static bool isRequired() { return true; }
    };

} // anonymous namespace

PassPluginLibraryInfo encryptionPass() {
    return {LLVM_PLUGIN_API_VERSION, "EncryptionPass", LLVM_VERSION_STRING,
            [](PassBuilder &PB) {
                PB.registerPipelineParsingCallback(
                    [&](StringRef name, ModulePassManager &MPM,
                        ArrayRef<PassBuilder::PipelineElement>) {
                        if (name == "encryption-pass") {
                            MPM.addPass(EncryptionPass());
                            return true;
                        }
                        return false;
                    });
            }};
}

extern "C" LLVM_ATTRIBUTE_WEAK PassPluginLibraryInfo llvmGetPassPluginInfo() {
    return encryptionPass();
}
