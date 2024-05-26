// System libs
#include <algorithm>
#include <iomanip>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include "llvm/ADT/Statistic.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Value.h"
#include "llvm/Pass.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/FormatVariadic.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Obfuscation/CryptoUtils.h"
#include "llvm/Transforms/Obfuscation/StringObfuscation.h"
#include "llvm/Transforms/Obfuscation/Utils.h"
#include "llvm/Transforms/Utils/GlobalStatus.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

#define DEBUG_TYPE "string-obfuscation"

using namespace llvm;

static cl::opt<uint32_t> ElementObfuscationProb(
    "strobf_prob", cl::init(100), cl::NotHidden,
    cl::desc("Choose the probability [%] each element of "
             "ConstantDataSequential will be "
             "obfuscated by the -strobf pass"));
static uint32_t ElementObfuscationProbTemp = 100;

using namespace std;
namespace llvm {

class StringObfuscation : public ModulePass {
public:
  static char ID;
  bool flag;
  struct CSPEntry {
    CSPEntry()
        : ID(0), Offset(0), DecGV(nullptr), DecStatus(nullptr),
          EncryptedStringTable(nullptr), DecFunc(nullptr) {}
    unsigned ID;
    unsigned Offset;
    GlobalVariable *DecGV;
    GlobalVariable *DecStatus; // is decrypted or not
    std::vector<uint8_t> Data;
    std::vector<uint8_t> EncKey;
    GlobalVariable *EncryptedStringTable;
    Function *DecFunc;
  };

  struct CSUser {
    CSUser(Type *ETy, GlobalVariable *User, GlobalVariable *NewGV)
        : Ty(ETy), GV(User), DecGV(NewGV), DecStatus(nullptr),
          InitFunc(nullptr) {}
    Type *Ty;
    GlobalVariable *GV;
    GlobalVariable *DecGV;
    GlobalVariable *DecStatus; // is decrypted or not
    Function *InitFunc;        // InitFunc will use decryted string to
    // initialize DecGV
  };

  std::vector<CSPEntry *> ConstantStringPool;
  std::map<GlobalVariable *, CSPEntry *> CSPEntryMap;
  std::map<GlobalVariable *, CSUser *> CSUserMap;
  // GlobalVariable *EncryptedStringTable = nullptr;
  std::set<GlobalVariable *> MaybeDeadGlobalVars;

  map<Function * /*Function*/, GlobalVariable * /*Decryption Status*/>
      encstatus;
  StringObfuscation() : ModulePass(ID) { this->flag = true; }
  StringObfuscation(bool flag) : ModulePass(ID) {
    this->flag = flag;
    // EncryptedStringTable = new GlobalVariable;
  }
  bool doFinalization(Module &) override {
    for (CSPEntry *Entry : ConstantStringPool) {
      delete (Entry);
    }
    for (auto &I : CSUserMap) {
      CSUser *User = I.second;
      delete (User);
    }
    ConstantStringPool.clear();
    CSPEntryMap.clear();
    CSUserMap.clear();
    MaybeDeadGlobalVars.clear();
    return false;
  }
  StringRef getPassName() const override { return "StringObfuscation"; }
  static bool isRequired() { return true; } // 直接返回true即可

  bool runOnModule(Module &M) override { // Pass实现函数
    outs() << "Running StringObfuscation\n";

    std::set<GlobalVariable *> ConstantStringUsers;

    // collect all c strings

    LLVMContext &Ctx = M.getContext();
    ConstantInt *Zero = ConstantInt::get(Type::getInt32Ty(Ctx), 0);
    for (GlobalVariable &GV : M.globals()) {
      if (!GV.isConstant() || !GV.hasInitializer() ||
          GV.hasDLLExportStorageClass() || GV.isDLLImportDependent()) {
        continue;
      }
      Constant *Init = GV.getInitializer();
      if (Init == nullptr)
        continue;
      if (ConstantDataSequential *CDS =
              dyn_cast<ConstantDataSequential>(Init)) {
        if (CDS->isCString()) {
          CSPEntry *Entry = new CSPEntry();
          StringRef Data = CDS->getRawDataValues();
          Entry->Data.reserve(Data.size());
          for (unsigned i = 0; i < Data.size(); ++i) {
            Entry->Data.push_back(static_cast<uint8_t>(Data[i]));
          }
          Entry->ID = static_cast<unsigned>(ConstantStringPool.size());
          ConstantAggregateZero *ZeroInit =
              ConstantAggregateZero::get(CDS->getType());
          GlobalVariable *DecGV = new GlobalVariable(
              M, CDS->getType(), false, GlobalValue::PrivateLinkage, ZeroInit,
              "dec_" + Twine::utohexstr(Entry->ID) + GV.getName());
          GlobalVariable *DecStatus = new GlobalVariable(
              M, Type::getInt32Ty(Ctx), false, GlobalValue::PrivateLinkage,
              Zero, "dec_status_" + Twine::utohexstr(Entry->ID) + GV.getName());
          DecGV->setAlignment(MaybeAlign(GV.getAlignment()));
          Entry->DecGV = DecGV;
          Entry->DecStatus = DecStatus;
          ConstantStringPool.push_back(Entry);
          CSPEntryMap[&GV] = Entry;
          collectConstantStringUser(&GV, ConstantStringUsers);
        }
      }
    }

    // encrypt those strings, build corresponding decrypt function
    for (CSPEntry *Entry : ConstantStringPool) {
      getRandomBytes(Entry->EncKey, 8, 32);
      for (unsigned i = 0; i < Entry->Data.size(); ++i) {
        Entry->Data[i] ^= Entry->EncKey[i % Entry->EncKey.size()];
      }
      Entry->DecFunc = buildDecryptFunction(&M, Entry);
    }

    // build initialization function for supported constant string users
    for (GlobalVariable *GV : ConstantStringUsers) {
      if (isValidToEncrypt(GV)) {
        Type *EltType = GV->getValueType();
        ConstantAggregateZero *ZeroInit = ConstantAggregateZero::get(EltType);
        GlobalVariable *DecGV =
            new GlobalVariable(M, EltType, false, GlobalValue::PrivateLinkage,
                               ZeroInit, "dec_" + GV->getName());
        DecGV->setAlignment(MaybeAlign(GV->getAlignment()));
        GlobalVariable *DecStatus = new GlobalVariable(
            M, Type::getInt32Ty(Ctx), false, GlobalValue::PrivateLinkage, Zero,
            "dec_status_" + GV->getName());
        CSUser *User = new CSUser(EltType, GV, DecGV);
        User->DecStatus = DecStatus;
        User->InitFunc = buildInitFunction(&M, User);
        CSUserMap[GV] = User;
      }
    }

    // emit the constant string pool
    // | junk bytes | key 1 | encrypted string 1 | junk bytes | key 2 |
    // encrypted string 2 | ...
    std::vector<uint8_t> Data;
    std::vector<uint8_t> JunkBytes;

    JunkBytes.reserve(16);
    for (CSPEntry *Entry : ConstantStringPool) {
      Data.clear();
      JunkBytes.clear();
      getRandomBytes(JunkBytes, 4, 16);
      Data.insert(Data.end(), JunkBytes.begin(), JunkBytes.end());
      Entry->Offset = static_cast<unsigned>(Data.size());
      Data.insert(Data.end(), Entry->EncKey.begin(), Entry->EncKey.end());
      Data.insert(Data.end(), Entry->Data.begin(), Entry->Data.end());
      JunkBytes.clear();
      getRandomBytes(JunkBytes, 4, 16);
      Data.insert(Data.end(), JunkBytes.begin(), JunkBytes.end());
      Constant *CDA =
          ConstantDataArray::get(M.getContext(), ArrayRef<uint8_t>(Data));
      string funcName = formatv("rise_encrypted_string_table_{0}",
                                Twine::utohexstr(Entry->ID));
      Entry->EncryptedStringTable = new GlobalVariable(
          M, CDA->getType(), true, GlobalValue::PrivateLinkage, CDA, funcName);
    }

    // Constant *CDA =
    //     ConstantDataArray::get(M.getContext(), ArrayRef<uint8_t>(Data));
    // EncryptedStringTable =
    //     new GlobalVariable(M, CDA->getType(), true,
    //     GlobalValue::PrivateLinkage,
    //                        CDA, "EncryptedStringTable");

    // decrypt string back at every use, change the plain string use to the
    // decrypted one
    bool Changed = false;
    for (Function &F : M) {
      if (F.isDeclaration())
        continue;
      Changed |= processConstantStringUse(&F);
    }

    for (auto &I : CSUserMap) {
      CSUser *User = I.second;
      Changed |= processConstantStringUse(User->InitFunc);
    }

    // delete unused global variables
    deleteUnusedGlobalVariable();
    for (CSPEntry *Entry : ConstantStringPool) {
      if (Entry->DecFunc->use_empty()) {
        Entry->DecFunc->eraseFromParent();
        Entry->DecGV->eraseFromParent();
        Entry->DecStatus->eraseFromParent();
        Entry->EncryptedStringTable->eraseFromParent();
      }
    }
    return Changed;
  }
  void collectConstantStringUser(GlobalVariable *CString,
                                 std::set<GlobalVariable *> &Users) {
    SmallPtrSet<Value *, 16> Visited;
    SmallVector<Value *, 16> ToVisit;

    ToVisit.push_back(CString);
    while (!ToVisit.empty()) {
      Value *V = ToVisit.pop_back_val();
      if (Visited.count(V) > 0)
        continue;
      Visited.insert(V);
      for (Value *User : V->users()) {
        if (auto *GV = dyn_cast<GlobalVariable>(User)) {
          Users.insert(GV);
        } else {
          ToVisit.push_back(User);
        }
      }
    }
  }
  bool isValidToEncrypt(GlobalVariable *GV) {
    if (GV->isConstant() && GV->hasInitializer()) {
      return GV->getInitializer() != nullptr;
    } else {
      return false;
    }
  }
  bool processConstantStringUse(Function *F) {
    if (!toObfuscate(flag, F, "strobf")) {
      return false;
    }
    if (!toObfuscateUint32Option(F, "strobf_prob", &ElementObfuscationProbTemp))
      ElementObfuscationProbTemp = ElementObfuscationProb;

    // Check if the number of applications is correct
    if (!((ElementObfuscationProbTemp > 0) &&
          (ElementObfuscationProbTemp <= 100))) {
      errs() << "StringObfuscation application element percentage "
                "-strobf_prob=x must be 0 < x <= 100";
      return false;
    }
    if (cryptoutils->get_range(100) >= ElementObfuscationProbTemp)
      return false;
    LowerConstantExpr(*F);
    SmallPtrSet<GlobalVariable *, 16>
        DecryptedGV; // if GV has multiple use in a block, decrypt only at the
                     // first use
    bool Changed = false;
    for (BasicBlock &BB : *F) {
      DecryptedGV.clear();
      if (BB.isEHPad()) {
        continue;
      }
      for (Instruction &Inst : BB) {
        if (Inst.isEHPad()) {
          continue;
        }
        if (PHINode *PHI = dyn_cast<PHINode>(&Inst)) {
          for (unsigned int i = 0; i < PHI->getNumIncomingValues(); ++i) {
            if (GlobalVariable *GV =
                    dyn_cast<GlobalVariable>(PHI->getIncomingValue(i))) {
              auto Iter1 = CSPEntryMap.find(GV);
              auto Iter2 = CSUserMap.find(GV);
              if (Iter2 != CSUserMap.end()) { // GV is a constant string user
                CSUser *User = Iter2->second;
                if (DecryptedGV.count(GV) > 0) {
                  Inst.replaceUsesOfWith(GV, User->DecGV);
                } else {
                  Instruction *InsertPoint =
                      PHI->getIncomingBlock(i)->getTerminator();
                  IRBuilder<> IRB(InsertPoint);
                  IRB.CreateCall(User->InitFunc, {User->DecGV});
                  Inst.replaceUsesOfWith(GV, User->DecGV);
                  MaybeDeadGlobalVars.insert(GV);
                  DecryptedGV.insert(GV);
                  Changed = true;
                }
              } else if (Iter1 !=
                         CSPEntryMap.end()) { // GV is a constant string
                CSPEntry *Entry = Iter1->second;
                if (DecryptedGV.count(GV) > 0) {
                  Inst.replaceUsesOfWith(GV, Entry->DecGV);
                } else {
                  Instruction *InsertPoint =
                      PHI->getIncomingBlock(i)->getTerminator();
                  IRBuilder<> IRB(InsertPoint);

                  Value *OutBuf =
                      IRB.CreateBitCast(Entry->DecGV, IRB.getInt8PtrTy());
                  Value *Data = IRB.CreateInBoundsGEP(
                      Entry->EncryptedStringTable->getValueType(),
                      Entry->EncryptedStringTable,
                      {IRB.getInt32(0), IRB.getInt32(Entry->Offset)});
                  IRB.CreateCall(Entry->DecFunc, {OutBuf, Data});

                  Inst.replaceUsesOfWith(GV, Entry->DecGV);
                  MaybeDeadGlobalVars.insert(GV);
                  DecryptedGV.insert(GV);
                  Changed = true;
                }
              }
            }
          }
        } else {
          for (User::op_iterator op = Inst.op_begin(); op != Inst.op_end();
               ++op) {
            if (GlobalVariable *GV = dyn_cast<GlobalVariable>(*op)) {
              auto Iter1 = CSPEntryMap.find(GV);
              auto Iter2 = CSUserMap.find(GV);
              if (Iter2 != CSUserMap.end()) {
                CSUser *User = Iter2->second;
                if (DecryptedGV.count(GV) > 0) {
                  Inst.replaceUsesOfWith(GV, User->DecGV);
                } else {
                  IRBuilder<> IRB(&Inst);
                  IRB.CreateCall(User->InitFunc, {User->DecGV});
                  Inst.replaceUsesOfWith(GV, User->DecGV);
                  MaybeDeadGlobalVars.insert(GV);
                  DecryptedGV.insert(GV);
                  Changed = true;
                }
              } else if (Iter1 != CSPEntryMap.end()) {
                CSPEntry *Entry = Iter1->second;
                if (DecryptedGV.count(GV) > 0) {
                  Inst.replaceUsesOfWith(GV, Entry->DecGV);
                } else {
                  IRBuilder<> IRB(&Inst);

                  Value *OutBuf =
                      IRB.CreateBitCast(Entry->DecGV, IRB.getInt8PtrTy());
                  Value *Data = IRB.CreateInBoundsGEP(
                      Entry->EncryptedStringTable->getValueType(),
                      Entry->EncryptedStringTable,
                      {IRB.getInt32(0), IRB.getInt32(Entry->Offset)});
                  IRB.CreateCall(Entry->DecFunc, {OutBuf, Data});

                  Inst.replaceUsesOfWith(GV, Entry->DecGV);
                  MaybeDeadGlobalVars.insert(GV);
                  DecryptedGV.insert(GV);
                  Changed = true;
                }
              }
            }
          }
        }
      }
    }
    return Changed;
  }
  void deleteUnusedGlobalVariable() {
    bool Changed = true;
    while (Changed) {
      Changed = false;
      for (auto Iter = MaybeDeadGlobalVars.begin();
           Iter != MaybeDeadGlobalVars.end();) {
        GlobalVariable *GV = *Iter;
        if (!GV->hasLocalLinkage()) {
          ++Iter;
          continue;
        }

        GV->removeDeadConstantUsers();
        if (GV->use_empty()) {
          if (GV->hasInitializer()) {
            Constant *Init = GV->getInitializer();
            GV->setInitializer(nullptr);
            if (isSafeToDestroyConstant(Init))
              Init->destroyConstant();
          }
          Iter = MaybeDeadGlobalVars.erase(Iter);
          GV->eraseFromParent();
          Changed = true;
        } else {
          ++Iter;
        }
      }
    }
  }

  Function *buildDecryptFunction(Module *M, const CSPEntry *Entry) {
    LLVMContext &Ctx = M->getContext();
    IRBuilder<> IRB(Ctx);
    FunctionType *FuncTy = FunctionType::get(
        Type::getVoidTy(Ctx),
        {Type::getInt8PtrTy(Ctx), Type::getInt8PtrTy(Ctx)}, false);
    string funcName =
        formatv("rise_decrypt_string_fun_{0}", Twine::utohexstr(Entry->ID));
    FunctionCallee callee = M->getOrInsertFunction(funcName, FuncTy);
    Function *DecFunc = cast<Function>(callee.getCallee());
    DecFunc->setCallingConv(CallingConv::C);
    DecFunc->setLinkage(GlobalValue::PrivateLinkage);
    Argument *PlainString = DecFunc->getArg(0);
    PlainString->setName("plain_string");
    DecFunc->addParamAttr(0, Attribute::NoCapture);
    Argument *Data = DecFunc->getArg(1);
    Data->setName("data");
    DecFunc->addParamAttr(1, Attribute::NoCapture);
    DecFunc->addParamAttr(1, Attribute::ReadOnly);

    BasicBlock *Enter = BasicBlock::Create(Ctx, "Enter", DecFunc);
    BasicBlock *LoopBody = BasicBlock::Create(Ctx, "LoopBody", DecFunc);
    BasicBlock *UpdateDecStatus =
        BasicBlock::Create(Ctx, "UpdateDecStatus", DecFunc);
    BasicBlock *Exit = BasicBlock::Create(Ctx, "Exit", DecFunc);

    IRB.SetInsertPoint(Enter);
    ConstantInt *KeySize =
        ConstantInt::get(Type::getInt32Ty(Ctx), Entry->EncKey.size());
    Value *EncPtr = IRB.CreateInBoundsGEP(IRB.getInt8Ty(), Data, KeySize);
    Value *DecStatus =
        IRB.CreateLoad(Entry->DecStatus->getValueType(), Entry->DecStatus);
    Value *IsDecrypted = IRB.CreateICmpEQ(DecStatus, IRB.getInt32(1));
    IRB.CreateCondBr(IsDecrypted, Exit, LoopBody);

    IRB.SetInsertPoint(LoopBody);
    PHINode *LoopCounter = IRB.CreatePHI(IRB.getInt32Ty(), 2);
    LoopCounter->addIncoming(IRB.getInt32(0), Enter);

    Value *EncCharPtr =
        IRB.CreateInBoundsGEP(IRB.getInt8Ty(), EncPtr, LoopCounter);
    Value *EncChar = IRB.CreateLoad(IRB.getInt8Ty(), EncCharPtr);
    Value *KeyIdx = IRB.CreateURem(LoopCounter, KeySize);

    Value *KeyCharPtr = IRB.CreateInBoundsGEP(IRB.getInt8Ty(), Data, KeyIdx);
    Value *KeyChar = IRB.CreateLoad(IRB.getInt8Ty(), KeyCharPtr);

    Value *DecChar = IRB.CreateXor(EncChar, KeyChar);
    Value *DecCharPtr =
        IRB.CreateInBoundsGEP(IRB.getInt8Ty(), PlainString, LoopCounter);
    IRB.CreateStore(DecChar, DecCharPtr);

    Value *NewCounter =
        IRB.CreateAdd(LoopCounter, IRB.getInt32(1), "", true, true);
    LoopCounter->addIncoming(NewCounter, LoopBody);

    Value *Cond = IRB.CreateICmpEQ(
        NewCounter, IRB.getInt32(static_cast<uint32_t>(Entry->Data.size())));
    IRB.CreateCondBr(Cond, UpdateDecStatus, LoopBody);

    IRB.SetInsertPoint(UpdateDecStatus);
    IRB.CreateStore(IRB.getInt32(1), Entry->DecStatus);
    IRB.CreateBr(Exit);

    IRB.SetInsertPoint(Exit);
    IRB.CreateRetVoid();

    return DecFunc;
  }

  Function *buildInitFunction(Module *M, const CSUser *User) {
    LLVMContext &Ctx = M->getContext();
    IRBuilder<> IRB(Ctx);
    FunctionType *FuncTy = FunctionType::get(Type::getVoidTy(Ctx),
                                             {User->DecGV->getType()}, false);
    Function *InitFunc = Function::Create(
        FuncTy, GlobalValue::PrivateLinkage,
        "__global_variable_initializer_" + User->GV->getName(), M);

    auto ArgIt = InitFunc->arg_begin();
    Argument *thiz = ArgIt;

    thiz->setName("this");
    thiz->addAttr(Attribute::NoCapture);

    // convert constant initializer into a series of instructions
    BasicBlock *Enter = BasicBlock::Create(Ctx, "Enter", InitFunc);
    BasicBlock *InitBlock = BasicBlock::Create(Ctx, "InitBlock", InitFunc);
    BasicBlock *Exit = BasicBlock::Create(Ctx, "Exit", InitFunc);

    IRB.SetInsertPoint(Enter);
    Value *DecStatus =
        IRB.CreateLoad(User->DecStatus->getValueType(), User->DecStatus);
    Value *IsDecrypted = IRB.CreateICmpEQ(DecStatus, IRB.getInt32(1));
    IRB.CreateCondBr(IsDecrypted, Exit, InitBlock);

    IRB.SetInsertPoint(InitBlock);
    Constant *Init = User->GV->getInitializer();
    lowerGlobalConstant(Init, IRB, User->DecGV, User->Ty);
    IRB.CreateStore(IRB.getInt32(1), User->DecStatus);
    IRB.CreateBr(Exit);

    IRB.SetInsertPoint(Exit);
    IRB.CreateRetVoid();
    return InitFunc;
  }

  void getRandomBytes(std::vector<uint8_t> &Bytes, uint32_t MinSize,
                      uint32_t MaxSize) {
    uint32_t N = cryptoutils->get_uint32_t();
    uint32_t Len;

    assert(MaxSize >= MinSize);

    if (MinSize == MaxSize) {
      Len = MinSize;
    } else {
      Len = MinSize + (N % (MaxSize - MinSize));
    }

    char *Buffer = new char[Len];
    cryptoutils->get_bytes(Buffer, Len);
    for (uint32_t i = 0; i < Len; ++i) {
      Bytes.push_back(static_cast<uint8_t>(Buffer[i]));
    }

    delete[] Buffer;
  }
  void lowerGlobalConstant(Constant *CV, IRBuilder<> &IRB, Value *Ptr,
                           Type *Ty) {
    if (isa<ConstantAggregateZero>(CV)) {
      IRB.CreateStore(CV, Ptr);
      return;
    }

    if (ConstantArray *CA = dyn_cast<ConstantArray>(CV)) {
      lowerGlobalConstantArray(CA, IRB, Ptr, Ty);
    } else if (ConstantStruct *CS = dyn_cast<ConstantStruct>(CV)) {
      lowerGlobalConstantStruct(CS, IRB, Ptr, Ty);
    } else {
      IRB.CreateStore(CV, Ptr);
    }
  };
  void lowerGlobalConstantStruct(ConstantStruct *CS, IRBuilder<> &IRB,
                                 Value *Ptr, Type *Ty) {
    for (unsigned i = 0, e = CS->getNumOperands(); i != e; ++i) {
      Constant *CV = CS->getOperand(i);
      Value *GEP = IRB.CreateGEP(Ty, Ptr, {IRB.getInt32(0), IRB.getInt32(i)});
      lowerGlobalConstant(CV, IRB, GEP, CV->getType());
    }
  };
  void lowerGlobalConstantArray(ConstantArray *CA, IRBuilder<> &IRB, Value *Ptr,
                                Type *Ty) {
    for (unsigned i = 0, e = CA->getNumOperands(); i != e; ++i) {
      Constant *CV = CA->getOperand(i);
      Value *GEP = IRB.CreateGEP(Ty, Ptr, {IRB.getInt32(0), IRB.getInt32(i)});
      lowerGlobalConstant(CV, IRB, GEP, CV->getType());
    }
  }
};
} // namespace llvm

// 创建字符串加密
ModulePass *llvm::createStringObfuscation() { return new StringObfuscation(); }
ModulePass *llvm::createStringObfuscation(bool flag) {
  return new StringObfuscation(flag);
}
char StringObfuscation::ID = 0;
INITIALIZE_PASS(StringObfuscation, "strobf", "Enable String Obfuscation", false,
                false)
