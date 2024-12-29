#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/TargetParser/TargetParser.h"
#include "llvm/Analysis/TargetTransformInfo.h"  // Corrected include
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

using namespace llvm;

const char *AnnotationString = "encrypt";

namespace {
    void findAnnotatedFunctions(Module &M) {
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
                        }
                    }
                }
            }
        }
    }

    void instantiateTargetMachine(Module &M) {
        // Initialize the target machine for the current architecture
        std::string TargetTriple = "x86_64-w64-mingw32";
        std::string Error;
        const Target *TheTarget = TargetRegistry::lookupTarget(TargetTriple, Error);
        if (!TheTarget) {
            errs() << "Error: " << Error << "\n";
            return;
        }

        TargetOptions Options;
        
        // Create a TargetMachine using std::move to manage the pointer properly
        std::unique_ptr<TargetMachine> Target(
            TheTarget->createTargetMachine(
                TargetTriple,           // Target triple (e.g., x86_64-linux-gnu)
                "generic",              // CPU name (you can specify your target CPU here)
                "",                     // Features (optional, can be left empty)
                Options,                // Target options
                std::nullopt,           // Relocation model (optional, set to std::nullopt)
                std::nullopt,           // Code model (optional, set to std::nullopt)
                CodeGenOpt::Default,    // Code generation optimization level
                false                   // JIT (Just-In-Time compilation) flag (false for regular compilation)
            )
        );

        if (!Target) {
            errs() << "Error: Could not create TargetMachine\n";
            return;
        }

        // Target machine has been instantiated, but no further actions are taken here.
        errs() << "Target machine instantiated for target: " << TargetTriple << "\n";
    }

    struct EncryptionPass : PassInfoMixin<EncryptionPass> {
        PreservedAnalyses run(Module &M, ModuleAnalysisManager &) {
            findAnnotatedFunctions(M);
            instantiateTargetMachine(M); // Just instantiate the target machine

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
