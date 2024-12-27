#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Passes/PassPlugin.h"

using namespace llvm;

namespace {
    void noop(Module &M) {
        // Iterate over all functions in the module
        for (Function &F : M) {
            continue;
        }
    }

    // New PM implementation for a transformation pass
    struct EncryptionPass : PassInfoMixin<EncryptionPass> {
        // Main entry point, takes IR unit to run the pass on (&M) and the
        // corresponding pass manager (to be queried if needed)
        PreservedAnalyses run(Module &M, ModuleAnalysisManager &MPM) {
            // Perform the transformation (replace 'add' with 'sub')
            noop(M);

            // Indicate that the module was transformed
            return PreservedAnalyses::none(); // Module is transformed (no-op analysis)
        }

        // This pass will not be skipped for functions decorated with optnone
        static bool isRequired() { return true; }
    };

} // anonymous namespace


//-----------------------------------------------------------------------------
// New PM Registration
//-----------------------------------------------------------------------------
PassPluginLibraryInfo getMyPassPluginInfo() {
    return {LLVM_PLUGIN_API_VERSION, "EncryptionPass", LLVM_VERSION_STRING, // callback following
        [](PassBuilder &PB) { // instantiate
            PB.registerPipelineParsingCallback(
            [&](StringRef name, ModulePassManager &MPM, ArrayRef<PassBuilder::PipelineElement>) {
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
