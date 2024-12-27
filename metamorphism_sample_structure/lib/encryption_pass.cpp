#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Constants.h"

using namespace llvm;

namespace {

    // As described in: https://sh4dy.com/2024/07/06/learning_llvm_02/
    void funp1(Module &M) {
        auto globals = M.globals();

        for(auto itr = globals.begin(); itr != globals.end(); itr++){
            StringRef varName = itr->getName();
            Type* ty = itr->getType();
            errs() << "Variable Name: " << varName << "\n";
            errs() << "Variable Type: ";
            ty->print(errs());
            errs() << "\n";
        }
    }

    // New PM implementation
    struct EncryptPass : PassInfoMixin<EncryptPass> {
        // Main entry point, takes IR unit to run the pass on (&M) and the
        // corresponding pass manager (to be queried if need be)
        PreservedAnalyses run(Module &M, ModuleAnalysisManager &MPM) {
            funp1(M);
            return PreservedAnalyses::all();
        }

        // Without isRequired returning true, this pass will be skipped for functions
        // decorated with the optnone LLVM attribute. Note that clang -O0 decorates
        // all functions with optnone.
        static bool isRequired() { return true; }
    };

} // anonymous namespace


//-----------------------------------------------------------------------------
// New PM Registration
//-----------------------------------------------------------------------------
PassPluginLibraryInfo getMyPassPluginInfo() {
    return {LLVM_PLUGIN_API_VERSION, "EncryptPass", LLVM_VERSION_STRING, //callback following
        [](PassBuilder &PB) { // instantiate
            PB.registerPipelineParsingCallback(
            [&](StringRef name, ModulePassManager &MPM, ArrayRef<PassBuilder::PipelineElement>) {
                if (name == "encrypt-pass") {
                    MPM.addPass(EncryptPass());
                    return true;
                }
                return false;
            });
    }};
}

extern "C" LLVM_ATTRIBUTE_WEAK PassPluginLibraryInfo llvmGetPassPluginInfo() {
    return getMyPassPluginInfo();
}