#include "llvm/Pass.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"

using namespace llvm;

namespace {
	struct Hello : public FunctionPass {
		static char ID;
		Hello() : FunctionPass(ID) {}
		bool runOnFunction(Function &F) override {
			errs() << "Hello: ";
			errs().write_escaped(F.getName()) << '\n';
			auto bbend = F.end();
			for (auto bbiter = F.begin(); bbiter != bbend; ++bbiter) {
				auto institer = bbiter->begin();
				auto instend = bbiter->end();
				for (; institer != instend; ++institer) {
					errs() << "OpcodeName: " << institer->getOpcodeName() << "\tNumOperands: " << institer->getNumOperands() << '\n';
					if (institer->getOpcode() == 56) {
						if (auto call_inst = dyn_cast<CallInst>(institer)) {
							errs() << call_inst->getCalledFunction()->getName() << '\n';
							for (int i = 0; i < institer->getNumOperands()-1; i++) {
								if(isa<ConstantInt>(call_inst->getOperand(i))) {
									errs() << "Operand " << i << " : " << dyn_cast<ConstantInt>(call_inst->getArgOperand(i))->getZExtValue() << '\n';
								}
							}
						}
					}
				}
			}
			return false;
		}

	};
}

char Hello::ID = 0;

static RegisterPass<Hello> X("hello", "Hello Pass", false, false);
	
static RegisterStandardPasses Y(PassManagerBuilder::EP_EarlyAsPossible,
[](const PassManagerBuilder &Builder, legacy::PassManagerBase &PM) {
});
