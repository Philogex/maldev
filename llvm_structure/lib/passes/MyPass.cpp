#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"        // Include for PassBuilder
#include "llvm/Passes/PassPlugin.h"         // Include for PassPluginLibraryInfo
#include "llvm/Support/raw_ostream.h"       // Include for printing

using namespace llvm;

namespace {

// This method implements what the pass does
void hello(Function &F) {
    errs() << "Hello: "<< F.getName() << "\n";
}

// New PM implementation
struct MyPass : PassInfoMixin<MyPass> {
  // Main entry point, takes IR unit to run the pass on (&F) and the
  // corresponding pass manager (to be queried if need be)
  PreservedAnalyses run(Function &F, FunctionAnalysisManager &) {
    hello(F);
    return PreservedAnalyses::all();
  }

  // Without isRequired returning true, this pass will be skipped for functions
  // decorated with the optnone LLVM attribute. Note that clang -O0 decorates
  // all functions with optnone.
  static bool isRequired() { return true; }
};
} // namespace

//-----------------------------------------------------------------------------
// New PM Registration
//-----------------------------------------------------------------------------
llvm::PassPluginLibraryInfo getMyPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "MyPass", LLVM_VERSION_STRING,
          [](PassBuilder &PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, FunctionPassManager &FPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                  if (Name == "my-pass") {
                    FPM.addPass(MyPass());
                    return true;
                  }
                  return false;
                });
          }};
}

// This is the core interface for pass plugins. It guarantees that 'opt' will
// be able to recognize MyPass when added to the pass pipeline on the
// command line, i.e. via '-passes=my-pass'
extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
  return getMyPassPluginInfo();
}