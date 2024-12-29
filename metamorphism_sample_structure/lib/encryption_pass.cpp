#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Passes/PassPlugin.h"

using namespace llvm;

const char *AnnotationString = "encrypt";

namespace {
    // Function to check if a function has the specific annotation
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

    // New PM implementation for a transformation pass
    struct EncryptionPass : PassInfoMixin<EncryptionPass> {
        PreservedAnalyses run(Module &M, ModuleAnalysisManager &) {
            findAnnotatedFunctions(M);
            return PreservedAnalyses::all(); // Indicate no transformation
        }

        static bool isRequired() { return true; }
    };

} // anonymous namespace

//-----------------------------------------------------------------------------
// New PM Registration
//-----------------------------------------------------------------------------
PassPluginLibraryInfo getMyPassPluginInfo() {
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
    return getMyPassPluginInfo();
}