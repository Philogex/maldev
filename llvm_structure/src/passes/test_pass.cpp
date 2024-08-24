#include "llvm/Pass.h"
#include "llvm/IR/Function.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

namespace {
    struct MyPass : public FunctionPass {
        static char ID;
        MyPass() : FunctionPass(ID) {}

        bool runOnFunction(Function &F) override {
            // Your pass logic here
            return false;
        }
    };
}

char MyPass::ID = 0;
static RegisterPass<MyPass> X("test_pass", "My Custom Pass", false, false);