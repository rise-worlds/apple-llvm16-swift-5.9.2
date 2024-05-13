#ifndef _STRING_OBFUSCATION_H_
#define _STRING_OBFUSCATION_H_
#include "llvm/Pass.h"

namespace llvm {
ModulePass *createStringObfuscation();
ModulePass *createStringObfuscation(bool flag);
void initializeStringObfuscationPass(PassRegistry &Registry);
} // namespace llvm

#endif