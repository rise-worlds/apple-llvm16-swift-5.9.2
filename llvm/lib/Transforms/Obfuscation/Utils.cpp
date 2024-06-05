// For open-source license, please refer to
// [License](https://github.com/HikariObfuscator/Hikari/wiki/License).
//===----------------------------------------------------------------------===//
#include "llvm/Transforms/Obfuscation/Utils.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/MDBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/NoFolder.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/FormatVariadic.h"
#include "llvm/Transforms/Utils/Local.h"
#include <set>
#include <sstream>

using namespace llvm;

namespace llvm {

    
std::string ToString(const Module &M) {
  std::error_code ec;
  std::string out;
  raw_string_ostream os(out);
  M.print(os, nullptr);
  return out;
}

std::string ToString(const Instruction &I) {
  std::string out;
  raw_string_ostream(out) << I;
  return out;
}

std::string ToString(const BasicBlock &BB) {
  std::string out;
  raw_string_ostream os(out);
  BB.printAsOperand(os, true);
  return out;
}

std::string ToString(const Type &Ty) {
  std::string out;
  raw_string_ostream os(out);
  os << TypeIDStr(Ty) << ": " << Ty;
  return out;
}

std::string ToString(const Value &V) {
  std::string out;
  raw_string_ostream os(out);
  os << ValueIDStr(V) << ": " << V;
  return out;
}

std::string ToString(const MDNode &N) {
  std::string out;
  raw_string_ostream os(out);
  N.printTree(os);
  return out;
}

std::string TypeIDStr(const Type &Ty) {
  switch (Ty.getTypeID()) {
  case Type::TypeID::HalfTyID:
    return "HalfTyID";
  case Type::TypeID::BFloatTyID:
    return "BFloatTyID";
  case Type::TypeID::FloatTyID:
    return "FloatTyID";
  case Type::TypeID::DoubleTyID:
    return "DoubleTyID";
  case Type::TypeID::X86_FP80TyID:
    return "X86_FP80TyID";
  case Type::TypeID::FP128TyID:
    return "FP128TyID";
  case Type::TypeID::PPC_FP128TyID:
    return "PPC_FP128TyID";
  case Type::TypeID::VoidTyID:
    return "VoidTyID";
  case Type::TypeID::LabelTyID:
    return "LabelTyID";
  case Type::TypeID::MetadataTyID:
    return "MetadataTyID";
  case Type::TypeID::X86_MMXTyID:
    return "X86_MMXTyID";
  case Type::TypeID::X86_AMXTyID:
    return "X86_AMXTyID";
  case Type::TypeID::TokenTyID:
    return "TokenTyID";
  case Type::TypeID::IntegerTyID:
    return "IntegerTyID";
  case Type::TypeID::FunctionTyID:
    return "FunctionTyID";
  case Type::TypeID::PointerTyID:
    return "PointerTyID";
  case Type::TypeID::StructTyID:
    return "StructTyID";
  case Type::TypeID::ArrayTyID:
    return "ArrayTyID";
  case Type::TypeID::FixedVectorTyID:
    return "FixedVectorTyID";
  case Type::TypeID::ScalableVectorTyID:
    return "ScalableVectorTyID";
  }
}

std::string ValueIDStr(const Value &V) {

#define HANDLE_VALUE(ValueName)                                                \
  case Value::ValueTy::ValueName##Val:                                         \
    return #ValueName;
  // #define HANDLE_INSTRUCTION(Name)  /* nothing */
  switch (V.getValueID()) {
#include "llvm/IR/Value.def"
  }

#define HANDLE_INST(N, OPC, CLASS)                                             \
  case N:                                                                      \
    return #CLASS;
  switch (V.getValueID() - Value::ValueTy::InstructionVal) {
#include "llvm/IR/Instruction.def"
#include <llvm/Support/FormatVariadic.h>
  }
  return std::to_string(V.getValueID());
}

size_t demotePHINode(Function &F) {
  size_t count = 0;
  std::vector<PHINode *> phiNodes;
  do {
    phiNodes.clear();
    for (auto &BB : F) {
      for (auto &I : BB.phis()) {
        phiNodes.push_back(&I);
      }
    }
    count += phiNodes.size();
    for (PHINode *phi : phiNodes) {
      DemotePHIToStack(phi, F.begin()->getTerminator());
    }
  } while (!phiNodes.empty());
  return count;
}

// Shamefully borrowed from ../Scalar/RegToMem.cpp :(
bool valueEscapes(Instruction *Inst) {
  BasicBlock *BB = Inst->getParent();
  for (Value::use_iterator UI = Inst->use_begin(), E = Inst->use_end(); UI != E;
       ++UI) {
    Instruction *I = cast<Instruction>(*UI);
    if (I->getParent() != BB || isa<PHINode>(I)) {
      return true;
    }
  }
  return false;
}

void fixStack(Function *f) {
  // Try to remove phi node and demote reg to stack
  SmallVector<PHINode *, 8> tmpPhi;
  SmallVector<Instruction *, 32> tmpReg;
  BasicBlock *bbEntry = &*f->begin();
  // Find first non-alloca instruction and create insertion point. This is
  // safe if block is well-formed: it always have terminator, otherwise
  // we'll get and assertion.
  BasicBlock::iterator I = bbEntry->begin();
  while (isa<AllocaInst>(I))
    ++I;
  Instruction *AllocaInsertionPoint = &*I;
  do {
    tmpPhi.clear();
    tmpReg.clear();
    for (BasicBlock &i : *f) {
      for (Instruction &j : i) {
        if (isa<PHINode>(&j)) {
          PHINode *phi = cast<PHINode>(&j);
          tmpPhi.emplace_back(phi);
          continue;
        }
        if (!(isa<AllocaInst>(&j) && j.getParent() == bbEntry) &&
            (valueEscapes(&j) || j.isUsedOutsideOfBlock(&i))) {
          tmpReg.emplace_back(&j);
          continue;
        }
      }
    }
    for (Instruction *I : tmpReg)
      DemoteRegToStack(*I, false, AllocaInsertionPoint);
    for (PHINode *P : tmpPhi)
      DemotePHIToStack(P, AllocaInsertionPoint);
  } while (tmpReg.size() != 0 || tmpPhi.size() != 0);
}

// Unlike O-LLVM which uses __attribute__ that is not supported by the ObjC
// CFE. We use a dummy call here and remove the call later Very dumb and
// definitely slower than the function attribute method Merely a hack
bool readFlag(Function *f, std::string attribute) {
  for (Instruction &I : instructions(f)) {
    Instruction *Inst = &I;
    if (CallInst *CI = dyn_cast<CallInst>(Inst)) {
      if (CI->getCalledFunction() != nullptr &&
          CI->getCalledFunction()->getName().contains("hikari_" + attribute)) {
        CI->eraseFromParent();
        return true;
      }
    }
  }
  return false;
}

bool toObfuscate(bool flag, Function *f, std::string attribute) {
  // Check if declaration and external linkage
  if (f->isDeclaration() || f->hasAvailableExternallyLinkage()) {
    return false;
  }
  std::string attr = attribute;
  std::string attrNo = "no" + attr;
  if (readAnnotationMetadata(f, attrNo) || readFlag(f, attrNo)) {
    return false;
  }
  if (readAnnotationMetadata(f, attr) || readFlag(f, attr)) {
    return true;
  }
  return flag;
}

bool toObfuscateBoolOption(Function *f, std::string option, bool *val) {
  std::string opt = option;
  std::string optDisable = "no" + option;
  if (readAnnotationMetadata(f, optDisable) || readFlag(f, optDisable)) {
    *val = false;
    return true;
  }
  if (readAnnotationMetadata(f, opt) || readFlag(f, opt)) {
    *val = true;
    return true;
  }
  return false;
}

static const char obfkindid[] = "MD_obf";

bool readAnnotationMetadataUint32OptVal(Function *f, std::string opt,
                                        uint32_t *val) {
  MDNode *Existing = f->getMetadata(obfkindid);
  if (Existing) {
    MDTuple *Tuple = cast<MDTuple>(Existing);
    for (auto &N : Tuple->operands()) {
      StringRef mdstr = cast<MDString>(N.get())->getString();
      std::string estr = opt + "=";
      if (mdstr.startswith(estr)) {
        *val = atoi(mdstr.substr(strlen(estr.c_str())).str().c_str());
        return true;
      }
    }
  }
  return false;
}

bool readFlagUint32OptVal(Function *f, std::string opt, uint32_t *val) {
  for (Instruction &I : instructions(f)) {
    Instruction *Inst = &I;
    if (CallInst *CI = dyn_cast<CallInst>(Inst)) {
      if (CI->getCalledFunction() != nullptr &&
          CI->getCalledFunction()->getName().contains("hikari_" + opt)) {
        if (ConstantInt *C = dyn_cast<ConstantInt>(CI->getArgOperand(0))) {
          *val = (uint32_t)C->getValue().getZExtValue();
          CI->eraseFromParent();
          return true;
        }
      }
    }
  }
  return false;
}

bool toObfuscateUint32Option(Function *f, std::string option, uint32_t *val) {
  if (readAnnotationMetadataUint32OptVal(f, option, val) ||
      readFlagUint32OptVal(f, option, val))
    return true;
  return false;
}

bool hasApplePtrauth(Module *M) {
  for (GlobalVariable &GV : M->globals())
    if (GV.getSection() == "llvm.ptrauth")
      return true;
  return false;
}

void FixBasicBlockConstantExpr(BasicBlock *BB) {
  // Replace ConstantExpr with equal instructions
  // Otherwise replacing on Constant will crash the compiler
  // Things to note:
  // - Phis must be placed at BB start so CEs must be placed prior to current BB
  assert(!BB->empty() && "BasicBlock is empty!");
  assert(BB->getParent() && "BasicBlock must be in a Function!");
  Instruction *FunctionInsertPt =
      &*(BB->getParent()->getEntryBlock().getFirstInsertionPt());

  for (Instruction &I : *BB) {
    if (isa<LandingPadInst>(I) || isa<FuncletPadInst>(I) ||
        isa<IntrinsicInst>(I))
      continue;
    for (unsigned int i = 0; i < I.getNumOperands(); i++)
      if (ConstantExpr *C = dyn_cast<ConstantExpr>(I.getOperand(i))) {
        IRBuilder<NoFolder> IRB(&I);
        if (isa<PHINode>(I))
          IRB.SetInsertPoint(FunctionInsertPt);
        Instruction *Inst = IRB.Insert(C->getAsInstruction());
        I.setOperand(i, Inst);
      }
  }
}

void FixFunctionConstantExpr(Function *Func) {
  // Replace ConstantExpr with equal instructions
  // Otherwise replacing on Constant will crash the compiler
  for (BasicBlock &BB : *Func)
    FixBasicBlockConstantExpr(&BB);
}

void turnOffOptimization(Function *f) {
  f->removeFnAttr(Attribute::AttrKind::MinSize);
  f->removeFnAttr(Attribute::AttrKind::OptimizeForSize);
  if (!f->hasFnAttribute(Attribute::AttrKind::OptimizeNone) &&
      !f->hasFnAttribute(Attribute::AttrKind::AlwaysInline)) {
    f->addFnAttr(Attribute::AttrKind::OptimizeNone);
    f->addFnAttr(Attribute::AttrKind::NoInline);
  }
}

static inline std::vector<std::string> splitString(std::string str) {
  std::stringstream ss(str);
  std::string word;
  std::vector<std::string> words;
  while (ss >> word)
    words.emplace_back(word);
  return words;
}

void annotation2Metadata(Module &M) {
  GlobalVariable *Annotations = M.getGlobalVariable("llvm.global.annotations");
  if (!Annotations)
    return;
  auto *C = dyn_cast<ConstantArray>(Annotations->getInitializer());
  if (!C)
    return;
  for (unsigned int i = 0; i < C->getNumOperands(); i++)
    if (ConstantStruct *CS = dyn_cast<ConstantStruct>(C->getOperand(i))) {
      GlobalValue *StrC =
          dyn_cast<GlobalValue>(CS->getOperand(1)->stripPointerCasts());
      if (!StrC)
        continue;
      ConstantDataSequential *StrData =
          dyn_cast<ConstantDataSequential>(StrC->getOperand(0));
      if (!StrData)
        continue;
      Function *Fn = dyn_cast<Function>(CS->getOperand(0)->stripPointerCasts());
      if (!Fn)
        continue;

      // Add annotation to the function.
      std::vector<std::string> strs =
          splitString(StrData->getAsCString().str());
      for (std::string str : strs)
        writeAnnotationMetadata(Fn, str);
    }
}

bool readAnnotationMetadata(Function *f, std::string annotation) {
  MDNode *Existing = f->getMetadata(obfkindid);
  if (Existing) {
    MDTuple *Tuple = cast<MDTuple>(Existing);
    for (auto &N : Tuple->operands())
      if (cast<MDString>(N.get())->getString() == annotation)
        return true;
  }
  return false;
}

void writeAnnotationMetadata(Function *f, std::string annotation) {
  LLVMContext &Context = f->getContext();
  MDBuilder MDB(Context);

  MDNode *Existing = f->getMetadata(obfkindid);
  SmallVector<Metadata *, 4> Names;
  bool AppendName = true;
  if (Existing) {
    MDTuple *Tuple = cast<MDTuple>(Existing);
    for (auto &N : Tuple->operands()) {
      if (cast<MDString>(N.get())->getString() == annotation)
        AppendName = false;
      Names.emplace_back(N.get());
    }
  }
  if (AppendName)
    Names.emplace_back(MDB.createString(annotation));

  MDNode *MD = MDTuple::get(Context, Names);
  f->setMetadata(obfkindid, MD);
}

bool AreUsersInOneFunction(GlobalVariable *GV) {
  SmallPtrSet<Function *, 6> userFunctions;
  for (User *U : GV->users()) {
    if (Instruction *I = dyn_cast<Instruction>(U)) {
      userFunctions.insert(I->getFunction());
    } else if (ConstantExpr *CE = dyn_cast<ConstantExpr>(U)) {
      for (User *U2 : CE->users()) {
        if (Instruction *I = dyn_cast<Instruction>(U2)) {
          userFunctions.insert(I->getFunction());
        }
      }
    } else {
      return false;
    }
  }
  return userFunctions.size() <= 1;
}

#if 0
std::map<GlobalValue *, StringRef> BuildAnnotateMap(Module &M) {
  std::map<GlobalValue *, StringRef> VAMap;
  GlobalVariable *glob = M.getGlobalVariable("llvm.global.annotations");
  if (glob != nullptr && glob->hasInitializer()) {
    ConstantArray *CDA = cast<ConstantArray>(glob->getInitializer());
    for (Value *op : CDA->operands()) {
      ConstantStruct *anStruct = cast<ConstantStruct>(op);
      /*
        Structure: [Value,Annotation,SourceFilePath,LineNumber]
        Usually wrapped inside GEP/BitCast
        We only care about Value and Annotation Here
      */
      GlobalValue *Value =
          cast<GlobalValue>(anStruct->getOperand(0)->getOperand(0));
      GlobalVariable *Annotation =
          cast<GlobalVariable>(anStruct->getOperand(1)->getOperand(0));
      if (Annotation->hasInitializer()) {
        VAMap[Value] =
            cast<ConstantDataSequential>(Annotation->getInitializer())
                ->getAsCString();
      }
    }
  }
  return VAMap;
}
#endif


/**
 * @brief 参考资料:https://www.jianshu.com/p/0567346fd5e8
 *        作用是读取llvm.global.annotations中的annotation值 从而实现过滤函数
 * 只对单独某功能开启PASS
 * @param f
 * @return std::string
 */
std::string readAnnotate(Function *f) { // 取自原版ollvm项目
  std::string annotation = "";
  /* Get annotation variable */
  GlobalVariable *glob =
      f->getParent()->getGlobalVariable("llvm.global.annotations");
  if (glob != NULL) {
    /* Get the array */
    if (ConstantArray *ca = dyn_cast<ConstantArray>(glob->getInitializer())) {
      for (unsigned i = 0; i < ca->getNumOperands(); ++i) {
        /* Get the struct */
        if (ConstantStruct *structAn =
                dyn_cast<ConstantStruct>(ca->getOperand(i))) {
          if (ConstantExpr *expr =
                  dyn_cast<ConstantExpr>(structAn->getOperand(0))) {
            /*
             * If it's a bitcast we can check if the annotation is concerning
             * the current function
             */
            if (expr->getOpcode() == Instruction::BitCast &&
                expr->getOperand(0) == f) {
              ConstantExpr *note = cast<ConstantExpr>(structAn->getOperand(1));
              /*
               * If it's a GetElementPtr, that means we found the variable
               * containing the annotations
               */
              if (note->getOpcode() == Instruction::GetElementPtr) {
                if (GlobalVariable *annoteStr =
                        dyn_cast<GlobalVariable>(note->getOperand(0))) {
                  if (ConstantDataSequential *data =
                          dyn_cast<ConstantDataSequential>(
                              annoteStr->getInitializer())) {
                    if (data->isString()) {
                      annotation += data->getAsString().lower() + " ";
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
  return (annotation);
}

/**
 * @brief 用于判断是否开启混淆
 *
 * @param flag
 * @param f
 * @param attribute
 * @return true
 * @return false
 */
bool toObfuscate(bool flag, Function *f,
                       std::string const &attribute) { // 取自原版ollvm项目
  std::string attr = attribute;
  std::string attrNo = "no" + attr;
  // Check if declaration
  if (f->isDeclaration()) {
    return false;
  }
  // Check external linkage
  if (f->hasAvailableExternallyLinkage() != 0) {
    return false;
  }
  // We have to check the nofla flag first
  // Because .find("fla") is true for a string like "fla" or
  // "nofla"
  if (readAnnotate(f).find(attrNo) != std::string::npos) { // 是否禁止开启XXX
    return false;
  }
  // If fla annotations
  if (readAnnotate(f).find(attr) != std::string::npos) { // 是否开启XXX
    return true;
  }
  // If fla flag is set
  if (flag == true) { // 开启PASS
    return true;
  }
  return false;
}

void llvm::LowerConstantExpr(Function &F) {
  SmallPtrSet<Instruction *, 8> WorkList;

  for (inst_iterator It = inst_begin(F), E = inst_end(F); It != E; ++It) {
    Instruction *I = &*It;

    if (isa<LandingPadInst>(I) || isa<CatchPadInst>(I) ||
        isa<CatchSwitchInst>(I) || isa<CatchReturnInst>(I))
      continue;
    if (auto *II = dyn_cast<IntrinsicInst>(I)) {
      if (II->getIntrinsicID() == Intrinsic::eh_typeid_for) {
        continue;
      }
    }

    for (unsigned int i = 0; i < I->getNumOperands(); ++i) {
      if (isa<ConstantExpr>(I->getOperand(i)))
        WorkList.insert(I);
    }
  }

  while (!WorkList.empty()) {
    auto It = WorkList.begin();
    Instruction *I = *It;
    WorkList.erase(*It);

    if (PHINode *PHI = dyn_cast<PHINode>(I)) {
      for (unsigned int i = 0; i < PHI->getNumIncomingValues(); ++i) {
        Instruction *TI = PHI->getIncomingBlock(i)->getTerminator();
        if (ConstantExpr *CE =
                dyn_cast<ConstantExpr>(PHI->getIncomingValue(i))) {
          Instruction *NewInst = CE->getAsInstruction();
          NewInst->insertBefore(TI);
          PHI->setIncomingValue(i, NewInst);
          WorkList.insert(NewInst);
        }
      }
    } else {
      for (unsigned int i = 0; i < I->getNumOperands(); ++i) {
        if (ConstantExpr *CE = dyn_cast<ConstantExpr>(I->getOperand(i))) {
          Instruction *NewInst = CE->getAsInstruction();
          NewInst->insertBefore(I);
          I->replaceUsesOfWith(CE, NewInst);
          WorkList.insert(NewInst);
        }
      }
    }
  }
}

void fatalError(const std::string &msg) { fatalError(msg.c_str()); }

void fatalError(const char *msg) {
  static LLVMContext Ctx;
  Ctx.emitError(msg);

  // emitError could return, so we make sure that we stop the execution
  errs() << llvm::formatv("Error: {}", msg);
  std::abort();
}

} // namespace llvm
