#ifndef _UTILS_H_
#define _UTILS_H_

#include "llvm/IR/Module.h"
#include <string>
#include <variant>

namespace llvm {

std::string ToString(const llvm::Module &M);
std::string ToString(const llvm::BasicBlock &BB);
std::string ToString(const llvm::Instruction &I);
std::string ToString(const llvm::Type &Ty);
std::string ToString(const llvm::Value &V);
std::string ToString(const llvm::MDNode &N);
std::string TypeIDStr(const Type &Ty);
std::string ValueIDStr(const Value &V);

size_t demotePHINode(Function &F);

void fatalError(const std::string &msg);
void fatalError(const char *msg);

std::string readAnnotate(Function *f); // 读取llvm.global.annotations中的annotation值
void fixStack(Function *f);
bool toObfuscate(bool flag, Function *f, std::string attribute);
bool toObfuscateBoolOption(Function *f, std::string option, bool *val);
bool toObfuscateUint32Option(Function *f, std::string option, uint32_t *val);
bool hasApplePtrauth(Module *M);
void FixFunctionConstantExpr(Function *Func);
void turnOffOptimization(Function *f);
void annotation2Metadata(Module &M);
bool readAnnotationMetadata(Function *f, std::string annotation);
void writeAnnotationMetadata(Function *f, std::string annotation);
bool AreUsersInOneFunction(GlobalVariable *GV);
void LowerConstantExpr(Function &F);
#if 0
std::map<GlobalValue*, StringRef> BuildAnnotateMap(Module& M);
#endif

} // namespace llvm

template <class... Ts> struct overloaded : Ts... {
  using Ts::operator()...;
};
template <class... Ts> overloaded(Ts...) -> overloaded<Ts...>;

#endif
