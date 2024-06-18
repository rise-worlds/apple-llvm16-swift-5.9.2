// System libs
#include <algorithm>
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
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
#include "llvm/Transforms/Obfuscation/Metadata.hpp"
#include "llvm/Transforms/Obfuscation/StringObfuscation.h"
#include "llvm/Transforms/Obfuscation/Utils.h"
#include "llvm/Transforms/Utils/GlobalStatus.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include <llvm/Demangle/Demangle.h>
#include <llvm/IR/NoFolder.h>
#include <llvm/Transforms/Utils/BasicBlockUtils.h>

#define DEBUG_TYPE "string-obfuscation"

using namespace llvm;

static cl::opt<uint32_t> ElementObfuscationProb("strobf_prob", cl::init(100), cl::NotHidden,
                                                cl::desc("Choose the probability [%] each element of "
                                                         "ConstantDataSequential will be "
                                                         "obfuscated by the -strobf pass"));
static uint32_t ElementObfuscationProbTemp = 100;

static cl::opt<uint32_t> ExpandStringMinLenght("strobf_expand_len", cl::init(10), cl::NotHidden,
                                               cl::desc("If the string is less than [%], "
                                                        "the calculation is directly expanded, by the -strobf pass"));
static uint32_t ExpandStringMinLenghtTemp = 10;

using namespace std;

namespace llvm {

GlobalVariable *extractGlobalVariable(ConstantExpr *Expr) {
    while (Expr) {
        if (Expr->getOpcode() == llvm::Instruction::IntToPtr || llvm::Instruction::isBinaryOp(Expr->getOpcode())) {
            Expr = dyn_cast<ConstantExpr>(Expr->getOperand(0));
        } else if (Expr->getOpcode() == llvm::Instruction::PtrToInt || Expr->getOpcode() == llvm::Instruction::GetElementPtr) {
            return dyn_cast<GlobalVariable>(Expr->getOperand(0));
        } else {
            break;
        }
    }

    return nullptr;
}

class StringObfuscation : public ModulePass {
  public:
    static char ID;
    bool Flag;
    struct CSPEntry : std::enable_shared_from_this<CSPEntry> {
        CSPEntry() = default;
        ~CSPEntry() = default;

        unsigned ID = 0;
        uint16_t Salt = 0;
        std::string OriginString;
        uint16_t OriginType = 0;

        GlobalVariable *DecGV = nullptr;
        GlobalVariable *DecStatus = nullptr; // is decrypted or not
        std::vector<uint8_t> EncData;
        std::vector<uint8_t> EncKey;
        GlobalVariable *EncryptedStringTable = nullptr;
        unsigned Offset = 0;
        unsigned EncKeySize = 0;
        Function *DecFunc = nullptr;

        AllocaInst *DecLV = nullptr;
        GlobalVariable *OriginGV = nullptr;
    };

    struct CSUser {
        CSUser(Type *ETy, GlobalVariable *User, GlobalVariable *NewGV)
            : Ty(ETy), GV(User), DecGV(NewGV), DecStatus(nullptr), InitFunc(nullptr) {}
        Type *Ty;
        GlobalVariable *GV;
        GlobalVariable *DecGV;
        GlobalVariable *DecStatus; // is decrypted or not
        Function *InitFunc;        // InitFunc will use decryted string to
                                   // initialize DecGV
    };

    std::vector<std::shared_ptr<CSPEntry>> ConstantStringPool;
    std::map<std::string, std::shared_ptr<CSPEntry>> ConstantStringMap;
    std::map<GlobalVariable *, std::shared_ptr<CSPEntry>> CSPEntryMap;
    std::map<GlobalVariable *, CSUser *> CSUserMap;
    // GlobalVariable *EncryptedStringTable = nullptr;
    std::set<GlobalVariable *> MaybeDeadGlobalVars;

    StringObfuscation() : ModulePass(ID) { this->Flag = true; }
    StringObfuscation(bool Flag) : ModulePass(ID) {
        this->Flag = Flag;
        // EncryptedStringTable = new GlobalVariable;
    }
    bool doFinalization(Module &) override {
        for (auto &I : CSUserMap) {
            CSUser *User = I.second;
            delete (User);
        }
        ConstantStringPool.clear();
        ConstantStringMap.clear();
        CSPEntryMap.clear();
        CSUserMap.clear();
        MaybeDeadGlobalVars.clear();
        return false;
    }
    StringRef getPassName() const override { return "StringObfuscation"; }
    static bool isRequired() { return true; }

    bool runOnModule(Module &M) override {
        errs() << "Running StringObfuscation flag: " << this->Flag << "\n";
        if (!this->Flag) {
            return false;
        }

        bool Changed = false;
        std::map<std::string, bool> function_obf_map;
        LLVMContext &Ctx = M.getContext();
        ConstantInt *Zero = ConstantInt::get(Type::getInt32Ty(Ctx), 0);
        for (Function &F : M) {
            std::string demangled = demangle(F.getName().str());
            errs() << "[StringObfuscation] " << demangled << "\n";

            if (!toObfuscate(Flag, &F, "strobf")) {
                // errs() << "[StringObfuscation] off, fun: " << demangled << ", flag: " << this->Flag << "\n";
                continue;
            }
            if (!toObfuscateUint32Option(&F, "strobf_prob", &ElementObfuscationProbTemp))
                ElementObfuscationProbTemp = ElementObfuscationProb;

            // Check if the number of applications is correct
            if (!((ElementObfuscationProbTemp > 0) && (ElementObfuscationProbTemp <= 100))) {
                errs() << "[StringObfuscation] application element percentage, fun: " << demangled
                       << ", -strobf_prob=x must be 0 < x <= 100\n";
                continue;
            }
            uint32_t ProbTemp = cryptoutils->get_range(100);
            if (ProbTemp > ElementObfuscationProbTemp) {
                errs() << "[StringObfuscation] off, fun: " << demangled << ", " << ProbTemp << "<=" << ElementObfuscationProbTemp << "\n";
                continue;
            }
            if (!toObfuscateUint32Option(&F, "strobf_expand_len", &ExpandStringMinLenghtTemp))
                ExpandStringMinLenghtTemp = ExpandStringMinLenght;

            FixFunctionConstantExpr(&F);
            Instruction *begin_ins = nullptr;
            for (BasicBlock &BB : F) {
                for (Instruction &I : BB) {
                    if (isa<PHINode>(I)) {
                        errs() << "[StringObfuscation] " << demangled << " contains Phi node which could raise issues !\n ";
                        continue;
                    }
                    if (begin_ins == nullptr) {
                        begin_ins = &I;
                    }

                    for (Use &Op : I.operands()) {
                        GlobalVariable *G = dyn_cast<GlobalVariable>(Op->stripPointerCasts());

                        if (!G)
                            continue;
                        // if (!G)
                        //     if (auto *CE = dyn_cast<ConstantExpr>(Op))
                        //         G = extractGlobalVariable(CE);
                        //
                        // auto IsInitializerConstantExpr = [](const GlobalVariable &G) {
                        //     return (!G.isExternallyInitialized() && G.hasInitializer()) && isa<ConstantExpr>(G.getInitializer());
                        // };
                        //
                        // Use *ActualOp = &Op;
                        // bool MaybeStringInCEInitializer = false;
                        // if (G && IsInitializerConstantExpr(*G)) {
                        //     // Is the global initializer part of a constant expression?
                        //     G = extractGlobalVariable(cast<ConstantExpr>(G->getInitializer()));
                        //     if (G) {
                        //         ActualOp = G->getSingleUndroppableUse();
                        //         MaybeStringInCEInitializer = true;
                        //     }
                        // }
                        //
                        // if (!G || !ActualOp)
                        //     continue;

                        if (G->isNullValue() || G->isZeroValue()) {
                            continue;
                        }
                        if (!(G->isConstant() && G->hasInitializer())) {
                            continue;
                        }
                        if (G->hasDLLExportStorageClass() || G->isDLLImportDependent()) {
                            continue;
                        }
                        if (G->getSection().startswith("llvm.")) {
                            continue;
                        }

                        auto *data = dyn_cast<ConstantDataSequential>(G->getInitializer());
                        if (data == nullptr) {
                            continue;
                        }
                        Type *memberType = data->getElementType();
                        // Ignore non-integer types
                        if (!memberType->isIntegerTy()) {
#if LLVM_VERSION_MAJOR >= 16
                            if (memberType->getTypeID() == 14) { // IntegerTyID is always 14 on AppleClang15, wtf
                                StringRef Str = data->getAsString();
                                if (Str.back() != 0) {
                                    continue;
                                }
                            } else
#endif
                                continue;
                        }

                        IntegerType *intType = cast<IntegerType>(memberType);
                        if (intType == Type::getInt8Ty(G->getParent()->getContext())) {
                            // std::string str = data->getRawDataValues().str();
                            // size_t StrSize = str.size();
                            // errs() << "[StringObfuscation] " << demangled << ": " << str << "\n";
                            size_t StrSize = data->getNumElements();
                            std::string str;
                            str.resize(StrSize);
                            for (unsigned i = 0; i < data->getNumElements(); i++) {
                                const uint32_t V = data->getElementAsInteger(i);
                                str[i] = static_cast<uint8_t>(V);
                            }

                            const auto &it = ConstantStringMap.find(str);
                            if (it != ConstantStringMap.end()) {
                                // if string has already been processed, replace it with the processed value
                                if (StrSize > ExpandStringMinLenghtTemp) {
                                    I.replaceUsesOfWith(G, it->second->DecGV);
                                } else {
                                    I.setOperand(Op.getOperandNo(), it->second->DecLV);
                                }
                            } else if (StrSize > ExpandStringMinLenghtTemp) {
                                std::shared_ptr<CSPEntry> pEntry = std::make_shared<CSPEntry>();
                                pEntry->ID = static_cast<unsigned>(ConstantStringPool.size());
                                pEntry->Salt = cryptoutils->get_range(0xffff);
                                pEntry->OriginGV = G;
                                pEntry->OriginString = str;
                                pEntry->OriginType = 8;
                                pEntry->EncKeySize = cryptoutils->get_range(8, 16);
                                pEntry->EncKey.resize(pEntry->EncKeySize);
                                std::generate(std::begin(pEntry->EncKey), std::end(pEntry->EncKey),
                                              []() { return cryptoutils->get_range(1, std::numeric_limits<uint8_t>::max()); });
                                pEntry->EncData.resize(StrSize);
                                for (size_t I = 0; I < StrSize; ++I) {
                                    pEntry->EncData[I] =
                                        static_cast<uint8_t>(str[I]) ^ static_cast<uint8_t>(pEntry->EncKey[I % pEntry->EncKeySize]);
                                }
                                ConstantAggregateZero *ZeroInit = ConstantAggregateZero::get(data->getType());
                                string DecName = formatv("rise_dec_{0}_{1}_{2}", G->getName(), Twine::utohexstr(pEntry->ID),
                                                         Twine::utohexstr(pEntry->Salt));
                                GlobalVariable *DecGV =
                                    new GlobalVariable(M, data->getType(), false, GlobalValue::PrivateLinkage, ZeroInit, DecName);
                                DecGV->setAlignment(MaybeAlign(G->getAlignment()));
                                pEntry->DecGV = DecGV;

                                std::vector<uint8_t> Data;
                                std::vector<uint8_t> JunkBytes;
                                JunkBytes.reserve(16);
                                getRandomBytes(JunkBytes, 4, 16);
                                Data.insert(Data.end(), JunkBytes.begin(), JunkBytes.end());
                                pEntry->Offset = static_cast<unsigned>(Data.size());
                                Data.insert(Data.end(), pEntry->EncKey.begin(), pEntry->EncKey.end());
                                Data.insert(Data.end(), pEntry->EncData.begin(), pEntry->EncData.end());
                                JunkBytes.clear();
                                getRandomBytes(JunkBytes, 2, 8);
                                Data.insert(Data.end(), JunkBytes.begin(), JunkBytes.end());
                                Constant *CDA = ConstantDataArray::get(Ctx, ArrayRef<uint8_t>(Data));
                                string EncName = formatv("rise_enc_{0}_{1}_{2}", G->getName(), Twine::utohexstr(pEntry->ID),
                                                         Twine::utohexstr(pEntry->Salt));
                                pEntry->EncryptedStringTable =
                                    new GlobalVariable(M, CDA->getType(), true, GlobalValue::PrivateLinkage, CDA, EncName);
                                ConstantStringPool.push_back(pEntry);
                                ConstantStringMap.emplace(str, pEntry);
                                I.replaceUsesOfWith(G, DecGV);
                                // if (G->use_empty()) {
                                //     G->eraseFromParent();
                                // }
                            } else {
                                std::shared_ptr<CSPEntry> pEntry = std::make_shared<CSPEntry>();
                                pEntry->ID = static_cast<unsigned>(ConstantStringPool.size());
                                pEntry->Salt = cryptoutils->get_range(0xffff);
                                pEntry->OriginGV = G;
                                pEntry->OriginString = str;
                                pEntry->OriginType = 8;
                                pEntry->EncKey.resize(StrSize);
                                std::generate(std::begin(pEntry->EncKey), std::end(pEntry->EncKey),
                                              []() { return cryptoutils->get_range(1, std::numeric_limits<uint8_t>::max()); });

                                pEntry->EncData.resize(StrSize);
                                for (size_t i = 0; i < StrSize; ++i) {
                                    pEntry->EncData[i] = static_cast<uint8_t>(str[i]) ^ static_cast<uint8_t>(pEntry->EncKey[i]);
                                }
                                string EncName = formatv("rise_enc_{0}_{1}_{2}", G->getName(), Twine::utohexstr(pEntry->ID),
                                                         Twine::utohexstr(pEntry->Salt));
                                Constant *CDA = ConstantDataArray::get(BB.getContext(), ArrayRef<uint8_t>(pEntry->EncData));
                                GlobalVariable *pEnc =
                                    new GlobalVariable(M, CDA->getType(), true, GlobalValue::PrivateLinkage, CDA, EncName);
                                // G->replaceAllUsesWith(pEnc);
                                I.replaceUsesOfWith(G, pEnc);
                                pEntry->EncryptedStringTable = pEnc;
                                ConstantStringMap.emplace(str, pEntry);

                                IRBuilder<NoFolder> IRB(begin_ins);
                                Use &EncPtr = Op;

                                // Allocate a buffer on the stack that contains the decoded string
                                string DecName = formatv("rise_dec_{0}_{1}_{2}", G->getName(), Twine::utohexstr(pEntry->ID),
                                                         Twine::utohexstr(pEntry->Salt));
                                AllocaInst *clearBuffer = IRB.CreateAlloca(IRB.getInt8Ty(), IRB.getInt32(StrSize), DecName);
                                pEntry->DecLV = clearBuffer;

                                llvm::SmallVector<size_t, 20> indexes(StrSize);
                                for (size_t i = 0; i < indexes.size(); ++i) {
                                    indexes[i] = i;
                                }
                                std::shuffle(indexes.begin(), indexes.end(), *cryptoutils->getEng());

                                for (size_t i = 0; i < StrSize; ++i) {
                                    size_t j = indexes[i];
                                    // Access the char in EncPtr[i]
                                    Value *encGEP =
                                        IRB.CreateGEP(IRB.getInt8Ty(), IRB.CreatePointerCast(EncPtr, IRB.getInt8PtrTy()), IRB.getInt32(j));

                                    // Load the encoded char
                                    LoadInst *encVal = IRB.CreateLoad(IRB.getInt8Ty(), encGEP);
                                    addMetadata(*encVal, MetaObf(PROTECT_FIELD_ACCESS));

                                    Value *decodedGEP = IRB.CreateGEP(IRB.getInt8Ty(), clearBuffer, IRB.getInt32(j));
                                    StoreInst *storeKey =
                                        IRB.CreateStore(ConstantInt::get(IRB.getInt8Ty(), (pEntry->EncKey)[j]), decodedGEP,
                                                        /* volatile */ true);
                                    addMetadata(*storeKey, {
                                                               MetaObf(PROTECT_FIELD_ACCESS),
                                                               MetaObf(OPAQUE_CST),
                                                           });

                                    LoadInst *keyVal = IRB.CreateLoad(IRB.getInt8Ty(), decodedGEP);
                                    addMetadata(*keyVal, MetaObf(PROTECT_FIELD_ACCESS));

                                    // Decode the value with xor
                                    Value *decVal = IRB.CreateXor(keyVal, encVal);

                                    if (auto *Op = dyn_cast<Instruction>(decVal)) {
                                        addMetadata(*Op, MetaObf(OPAQUE_OP, 2llu));
                                    }

                                    // Store the value
                                    StoreInst *storeClear = IRB.CreateStore(decVal, decodedGEP, /* volatile */ true);
                                    addMetadata(*storeClear, MetaObf(PROTECT_FIELD_ACCESS));
                                }

                                I.setOperand(Op.getOperandNo(), clearBuffer);
                                // if (G->use_empty()) {
                                //     G->removeFromParent();
                                // }
                            }

                            function_obf_map[F.getName().str()] = true;
                            Changed |= true;
#pragma region disable int16/int32
                            //} else if (intType == Type::getInt16Ty(G->getParent()->getContext())) {
                            //    std::vector<uint16_t> str;
                            //    for (unsigned i = 0; i < data->getNumElements(); i++) {
                            //        const uint64_t V = data->getElementAsInteger(i);
                            //        str.emplace_back(V);
                            //    }
                            //    size_t StrSize = str.size();
                            //
                            //    if (StrSize > 10) {
                            //        CSPEntry *Entry = new CSPEntry();
                            //
                            //        std::vector<uint16_t> encKey;
                            //        getRandomBytes(encKey, 8, 16);
                            //        int EncKeySize = encKey.size();
                            //        // Entry->Data.reserve(StrSize);
                            //        // for (unsigned I = 0; I < StrSize; ++I) {
                            //        //     Entry->Data.push_back(static_cast<uint16_t>(str[I]) ^ Entry->EncKey[I % EncKeySize]);
                            //        // }
                            //        Entry->KeySize = EncKeySize;
                            //        Entry->EncKey.resize(EncKeySize);
                            //        Entry->Data.resize(StrSize);
                            //        std::vector<uint16_t> encoded(StrSize);
                            //        for (size_t I = 0; I < StrSize; ++I) {
                            //            // encoded[I] = static_cast<uint16_t>(str[I]) ^ static_cast<uint16_t>(Entry->EncKey[I %
                            //            EncKeySize]); encoded[I] = static_cast<uint16_t>(str[I]) ^ static_cast<uint16_t>(encKey[I %
                            //            EncKeySize]);
                            //        }
                            //        Entry->ID = static_cast<unsigned>(ConstantStringPool.size());
                            //        Entry->Salt = cryptoutils->get_range(0xffff);
                            //        ConstantAggregateZero *ZeroInit = ConstantAggregateZero::get(data->getType());
                            //        string DecName = formatv("rise_dec_{0}_{1}_{2}", G->getName(), Twine::utohexstr(Entry->ID),
                            //                                 Twine::utohexstr(Entry->Salt));
                            //        GlobalVariable *DecGV =
                            //            new GlobalVariable(M, data->getType(), false, GlobalValue::PrivateLinkage, //ZeroInit, DecName);
                            //        DecGV->setAlignment(MaybeAlign(G->getAlignment()));
                            //        Entry->DecGV = DecGV;
                            //
                            //        std::vector<uint16_t> Data;
                            //        std::vector<uint16_t> JunkBytes;
                            //        JunkBytes.reserve(16);
                            //        getRandomBytes(JunkBytes, 4, 16);
                            //        Data.insert(Data.end(), JunkBytes.begin(), JunkBytes.end());
                            //        Entry->Offset = static_cast<unsigned>(Data.size());
                            //        // Data.insert(Data.end(), Entry->EncKey.begin(), Entry->EncKey.end());
                            //        // Data.insert(Data.end(), Entry->Data.begin(), Entry->Data.end());
                            //        Data.insert(Data.end(), encKey.begin(), encKey.end());
                            //        Data.insert(Data.end(), encoded.begin(), encoded.end());
                            //        JunkBytes.clear();
                            //        getRandomBytes(JunkBytes, 2, 8);
                            //        Data.insert(Data.end(), JunkBytes.begin(), JunkBytes.end());
                            //        Constant *CDA = ConstantDataArray::get(Ctx, ArrayRef<uint16_t>(Data));
                            //        string encStringName = formatv("rise_enc_{0}_{1}_{2}", G->getName(), Twine::utohexstr(Entry->ID),
                            //                                       Twine::utohexstr(Entry->Salt));
                            //        Entry->EncryptedStringTable =
                            //            new GlobalVariable(M, CDA->getType(), true, GlobalValue::PrivateLinkage, //CDA, encStringName);
                            //        ConstantStringPool.push_back(Entry);
                            //        I.replaceUsesOfWith(G, DecGV);
                            //        if (G->use_empty()) {
                            //            G->eraseFromParent();
                            //        }
                            //    } else {
                            //        std::vector<uint16_t> key(StrSize);
                            //        std::generate(std::begin(key), std::end(key),
                            //                      []() { return cryptoutils->get_range(1, //std::numeric_limits<uint16_t>::max() - 1); });
                            //        int temp = cryptoutils->get_range(0xffff);
                            //
                            //        std::vector<uint16_t> encoded(str.size());
                            //        for (size_t i = 0; i < str.size(); ++i) {
                            //            encoded[i] = static_cast<uint16_t>(str[i]) ^ static_cast<uint16_t>(key[i]);
                            //        }
                            //        string EncName = formatv("rise_enc_{0}_{1}", G->getName(), Twine::utohexstr(temp));
                            //        Constant *StrEnc = ConstantDataArray::get(BB.getContext(), ArrayRef<uint16_t>(encoded));
                            //        GlobalVariable *pEnc =
                            //            new GlobalVariable(M, StrEnc->getType(), true, GlobalValue::PrivateLinkage, //StrEnc, EncName);
                            //        G->replaceAllUsesWith(pEnc);
                            //
                            //        IRBuilder<NoFolder> IRB(&BB);
                            //        IRB.SetInsertPoint(&I);
                            //        Use &EncPtr = Op;
                            //
                            //        // Allocate a buffer on the stack that contains the decoded string
                            //        string DecName = formatv("rise_dec_{0}_{1}", G->getName(), Twine::utohexstr(temp));
                            //        AllocaInst *clearBuffer = IRB.CreateAlloca(IRB.getInt16Ty(), IRB.getInt32(StrSize), //DecName);
                            //
                            //        llvm::SmallVector<size_t, 20> indexes(StrSize);
                            //        for (size_t i = 0; i < indexes.size(); ++i) {
                            //            indexes[i] = i;
                            //        }
                            //        std::shuffle(indexes.begin(), indexes.end(), *cryptoutils->getEng());
                            //
                            //        for (size_t i = 0; i < StrSize; ++i) {
                            //            size_t j = indexes[i];
                            //            // Access the char in EncPtr[i]
                            //            Value *encGEP =
                            //                IRB.CreateGEP(IRB.getInt16Ty(), IRB.CreatePointerCast(EncPtr, IRB.getInt8PtrTy()),
                            //                //IRB.getInt32(j));
                            //
                            //            // Load the encoded char
                            //            LoadInst *encVal = IRB.CreateLoad(IRB.getInt16Ty(), encGEP);
                            //            addMetadata(*encVal, MetaObf(PROTECT_FIELD_ACCESS));
                            //
                            //            Value *decodedGEP = IRB.CreateGEP(IRB.getInt16Ty(), clearBuffer, IRB.getInt32(j));
                            //            StoreInst *storeKey = IRB.CreateStore(ConstantInt::get(IRB.getInt16Ty(), (key)[j]), //decodedGEP,
                            //                                                  /* volatile */ true);
                            //
                            //            addMetadata(*storeKey, {
                            //                                       MetaObf(PROTECT_FIELD_ACCESS),
                            //                                       MetaObf(OPAQUE_CST),
                            //                                   });
                            //
                            //            LoadInst *keyVal = IRB.CreateLoad(IRB.getInt16Ty(), decodedGEP);
                            //            addMetadata(*keyVal, MetaObf(PROTECT_FIELD_ACCESS));
                            //
                            //            // Decode the value with xor
                            //            Value *decVal = IRB.CreateXor(keyVal, encVal);
                            //
                            //            if (auto *Op = dyn_cast<Instruction>(decVal)) {
                            //                addMetadata(*Op, MetaObf(OPAQUE_OP, 2llu));
                            //            }
                            //
                            //            // Store the value
                            //            StoreInst *storeClear = IRB.CreateStore(decVal, decodedGEP, /* volatile */ true);
                            //            addMetadata(*storeClear, MetaObf(PROTECT_FIELD_ACCESS));
                            //        }
                            //
                            //        I.setOperand(Op.getOperandNo(), clearBuffer);
                            //        if (G->use_empty()) {
                            //            G->removeFromParent();
                            //        }
                            //    }
                            //
                            //    Changed |= true;
                            //} else if (intType == Type::getInt32Ty(G->getParent()->getContext())) {
                            //    std::vector<uint32_t> str;
                            //    for (unsigned i = 0; i < data->getNumElements(); i++) {
                            //        const uint64_t V = data->getElementAsInteger(i);
                            //        str.emplace_back(V);
                            //    }
                            //    size_t StrSize = str.size();
                            //
                            //    if (StrSize > 10) {
                            //        CSPEntry *Entry = new CSPEntry();
                            //
                            //        std::vector<uint32_t> encKey;
                            //        getRandomBytes(encKey, 8, 16);
                            //        int EncKeySize = encKey.size();
                            //        // Entry->Data.reserve(StrSize);
                            //        // for (unsigned I = 0; I < StrSize; ++I) {
                            //        //     Entry->Data.push_back(static_cast<uint16_t>(str[I]) ^ Entry->EncKey[I % EncKeySize]);
                            //        // }
                            //        Entry->KeySize = EncKeySize;
                            //        Entry->EncKey.resize(EncKeySize);
                            //        Entry->Data.resize(StrSize);
                            //        std::vector<uint32_t> encoded(StrSize);
                            //        for (size_t I = 0; I < StrSize; ++I) {
                            //            // encoded[I] = static_cast<uint16_t>(str[I]) ^ static_cast<uint16_t>(Entry->EncKey[I %
                            //            EncKeySize]); encoded[I] = static_cast<uint32_t>(str[I]) ^ static_cast<uint32_t>(encKey[I %
                            //            EncKeySize]);
                            //        }
                            //        Entry->ID = static_cast<unsigned>(ConstantStringPool.size());
                            //        Entry->Salt = cryptoutils->get_range(0xffff);
                            //        ConstantAggregateZero *ZeroInit = ConstantAggregateZero::get(data->getType());
                            //        string DecName = formatv("rise_dec_{0}_{1}_{2}", G->getName(), Twine::utohexstr(Entry->ID),
                            //                                 Twine::utohexstr(Entry->Salt));
                            //        GlobalVariable *DecGV =
                            //            new GlobalVariable(M, data->getType(), false, GlobalValue::PrivateLinkage, //ZeroInit, DecName);
                            //        DecGV->setAlignment(MaybeAlign(G->getAlignment()));
                            //        Entry->DecGV = DecGV;
                            //
                            //        std::vector<uint32_t> Data;
                            //        std::vector<uint32_t> JunkBytes;
                            //        JunkBytes.reserve(16);
                            //        getRandomBytes(JunkBytes, 4, 16);
                            //        Data.insert(Data.end(), JunkBytes.begin(), JunkBytes.end());
                            //        Entry->Offset = static_cast<unsigned>(Data.size());
                            //        // Data.insert(Data.end(), Entry->EncKey.begin(), Entry->EncKey.end());
                            //        // Data.insert(Data.end(), Entry->Data.begin(), Entry->Data.end());
                            //        Data.insert(Data.end(), encKey.begin(), encKey.end());
                            //        Data.insert(Data.end(), encoded.begin(), encoded.end());
                            //        JunkBytes.clear();
                            //        getRandomBytes(JunkBytes, 2, 8);
                            //        Data.insert(Data.end(), JunkBytes.begin(), JunkBytes.end());
                            //        Constant *CDA = ConstantDataArray::get(Ctx, ArrayRef<uint32_t>(Data));
                            //        string encStringName = formatv("rise_enc_{0}_{1}_{2}", G->getName(), Twine::utohexstr(Entry->ID),
                            //                                       Twine::utohexstr(Entry->Salt));
                            //        Entry->EncryptedStringTable =
                            //            new GlobalVariable(M, CDA->getType(), true, GlobalValue::PrivateLinkage, //CDA, encStringName);
                            //        ConstantStringPool.push_back(Entry);
                            //        I.replaceUsesOfWith(G, DecGV);
                            //        if (G->use_empty()) {
                            //            G->eraseFromParent();
                            //        }
                            //    } else {
                            //        std::vector<uint32_t> key(StrSize);
                            //        std::generate(std::begin(key), std::end(key),
                            //                      []() { return cryptoutils->get_range(1, //std::numeric_limits<uint32_t>::max() - 1); });
                            //        int temp = cryptoutils->get_range(0xffff);
                            //
                            //        std::vector<uint32_t> encoded(str.size());
                            //        for (size_t i = 0; i < str.size(); ++i) {
                            //            encoded[i] = static_cast<uint32_t>(str[i]) ^ static_cast<uint32_t>(key[i]);
                            //        }
                            //        string EncName = formatv("rise_enc_{0}_{1}", G->getName(), Twine::utohexstr(temp));
                            //        Constant *StrEnc = ConstantDataArray::get(BB.getContext(), ArrayRef<uint32_t>(encoded));
                            //        GlobalVariable *pEnc =
                            //            new GlobalVariable(M, StrEnc->getType(), true, GlobalValue::PrivateLinkage, //StrEnc, EncName);
                            //        G->replaceAllUsesWith(pEnc);
                            //
                            //        IRBuilder<NoFolder> IRB(&BB);
                            //        IRB.SetInsertPoint(&I);
                            //        Use &EncPtr = Op;
                            //
                            //        // Allocate a buffer on the stack that contains the decoded string
                            //        string DecName = formatv("rise_dec_{0}_{1}", G->getName(), Twine::utohexstr(temp));
                            //        AllocaInst *clearBuffer = IRB.CreateAlloca(IRB.getInt32Ty(), IRB.getInt32(StrSize), //DecName);
                            //
                            //        llvm::SmallVector<size_t, 20> indexes(StrSize);
                            //        for (size_t i = 0; i < indexes.size(); ++i) {
                            //            indexes[i] = i;
                            //        }
                            //        std::shuffle(indexes.begin(), indexes.end(), *cryptoutils->getEng());
                            //
                            //        for (size_t i = 0; i < StrSize; ++i) {
                            //            size_t j = indexes[i];
                            //            // Access the char in EncPtr[i]
                            //            Value *encGEP =
                            //                IRB.CreateGEP(IRB.getInt32Ty(), IRB.CreatePointerCast(EncPtr, IRB.getInt8PtrTy()),
                            //                //IRB.getInt32(j));
                            //
                            //            // Load the encoded char
                            //            LoadInst *encVal = IRB.CreateLoad(IRB.getInt32Ty(), encGEP);
                            //            addMetadata(*encVal, MetaObf(PROTECT_FIELD_ACCESS));
                            //
                            //            Value *decodedGEP = IRB.CreateGEP(IRB.getInt32Ty(), clearBuffer, IRB.getInt32(j));
                            //            StoreInst *storeKey = IRB.CreateStore(ConstantInt::get(IRB.getInt32Ty(), (key)[j]), //decodedGEP,
                            //                                                  /* volatile */ true);
                            //
                            //            addMetadata(*storeKey, {
                            //                                       MetaObf(PROTECT_FIELD_ACCESS),
                            //                                       MetaObf(OPAQUE_CST),
                            //                                   });
                            //
                            //            LoadInst *keyVal = IRB.CreateLoad(IRB.getInt32Ty(), decodedGEP);
                            //            addMetadata(*keyVal, MetaObf(PROTECT_FIELD_ACCESS));
                            //
                            //            // Decode the value with xor
                            //            Value *decVal = IRB.CreateXor(keyVal, encVal);
                            //
                            //            if (auto *Op = dyn_cast<Instruction>(decVal)) {
                            //                addMetadata(*Op, MetaObf(OPAQUE_OP, 2llu));
                            //            }
                            //
                            //            // Store the value
                            //            StoreInst *storeClear = IRB.CreateStore(decVal, decodedGEP, /* volatile */ true);
                            //            addMetadata(*storeClear, MetaObf(PROTECT_FIELD_ACCESS));
                            //        }
                            //
                            //        I.setOperand(Op.getOperandNo(), clearBuffer);
                            //        if (G->use_empty()) {
                            //            G->removeFromParent();
                            //        }
                            //    }
                            //
                            //    Changed |= true;
#pragma endregion
                        } else {
                            errs() << "[StringObfuscation] Unprocessed type: " << intType->getTypeID() << ", " << data->getRawDataValues()
                                   << "\n";
                        }
                    }
                }
            }

            for (auto &it : ConstantStringMap) {
                std::shared_ptr<CSPEntry> Entery = it.second;
                //  if the original string is no referenced, and released it
                if (Entery->OriginGV->use_empty()) {
                    Entery->OriginGV->removeFromParent();
                }
            }
            ConstantStringMap.clear();

            if (ConstantStringPool.empty())
                continue;

            Constant *S = ConstantInt::getNullValue(Type::getInt32Ty(Ctx));
            GlobalVariable *StatusGV =
                new GlobalVariable(M, S->getType(), false, GlobalValue::LinkageTypes::PrivateLinkage, S, "StringEncStatus");

            BasicBlock *A = &(F.getEntryBlock());
            BasicBlock *D = A->splitBasicBlock(A->getFirstNonPHIOrDbgOrLifetime(), "PrecedingBlock");
            BasicBlock *B = BasicBlock::Create(F.getContext(), "LoadStringDecBB", &F, D);
            // Change the terminal instruction of A to jump to B, and a new terminal instruction will be added later to jump to C
            BranchInst *NewBr = BranchInst::Create(B);
            ReplaceInstWithInst(A->getTerminator(), NewBr);
            IRBuilder<> IRB(A->getFirstNonPHIOrDbgOrLifetime());

            // Add atomic loads in A to check status
            LoadInst *LI = IRB.CreateLoad(IRB.getInt32Ty(), StatusGV, "LoadStringEncStatus");
            LI->setAtomic(AtomicOrdering::Acquire); // Will be released at the beginning of C
            LI->setAlignment(Align(4));

            Value *ZeroValue = ConstantInt::get(IRB.getInt32Ty(), 0);
            Value *Condition = IRB.CreateICmpEQ(LI, ZeroValue);
            A->getTerminator()->eraseFromParent();
            BranchInst::Create(B, D, Condition, A);

            // Insert decrypt code block
            IRBuilder<> IRB_B(B);
            for (std::shared_ptr<CSPEntry> Entry : ConstantStringPool) {
                uint16_t tempId = cryptoutils->get_uint32_t();
                // Create an initialization block for the loop
                std::string headName = formatv("loop.head.{0}", tempId);
                BasicBlock *loopHeadBlock = BasicBlock::Create(Ctx, headName, &F, D);
                // Create a conditional block for the loop
                std::string condName = formatv("loop.cond.{0}", tempId);
                BasicBlock *loopCondBlock = BasicBlock::Create(Ctx, condName, &F, D);
                // Create a loop block
                std::string bodyName = formatv("loop.body.{0}", tempId);
                BasicBlock *loopBodyBlock = BasicBlock::Create(Ctx, bodyName, &F, D);
                // Create the block at the end of the loop
                std::string endName = formatv("loop.end.{0}", tempId);
                BasicBlock *loopEndBlock = BasicBlock::Create(Ctx, endName, &F, D);

                IRB_B.CreateBr(loopHeadBlock);
                IRB_B.SetInsertPoint(loopHeadBlock);
                Value *Size = ConstantInt::get(IRB_B.getInt32Ty(), Entry->EncData.size());
                // Creates a loop variable i of type 32-bit integer
                Value *i = IRB_B.CreateAlloca(IRB_B.getInt32Ty(), nullptr, "i");
                IRB_B.CreateStore(IRB_B.getInt32(0), i); // Initialize i to 0

                Value *OutBuf = IRB_B.CreateBitCast(Entry->DecGV, IRB_B.getInt8PtrTy());
                Value *Data = IRB_B.CreateInBoundsGEP(Entry->EncryptedStringTable->getValueType(), Entry->EncryptedStringTable,
                                                      {IRB_B.getInt32(0), IRB_B.getInt32(Entry->Offset)});
                ConstantInt *KeySize = ConstantInt::get(Type::getInt32Ty(Ctx), Entry->EncKey.size());
                Value *EncPtr = IRB_B.CreateInBoundsGEP(IRB_B.getInt8Ty(), Data, KeySize);

                IRB_B.CreateBr(loopCondBlock);
                IRB_B.SetInsertPoint(loopCondBlock);

                // Load the value of the loop variable i
                Value *iValue = IRB_B.CreateLoad(IRB_B.getInt32Ty(), i);
                // Compares whether the value of i is less than strSize and create a conditional branch accordingly
                std::string loopCondName = formatv("loop.cond.le.{0}", tempId);
                Value *cond = IRB_B.CreateICmpULT(iValue, Size, loopCondName);
                IRB_B.CreateCondBr(cond, loopBodyBlock, loopEndBlock);

                // Set the IRBuilder insertion point to a loop block
                IRB_B.SetInsertPoint(loopBodyBlock);

                // Perform an XOR calculation on value[i] using key[i]
                Value *EncCharPtr = IRB_B.CreateInBoundsGEP(IRB_B.getInt8Ty(), EncPtr, iValue);
                Value *EncChar = IRB_B.CreateLoad(IRB_B.getInt8Ty(), EncCharPtr);

                Value *KeyIdx = IRB_B.CreateURem(iValue, KeySize);
                Value *KeyCharPtr = IRB_B.CreateInBoundsGEP(IRB_B.getInt8Ty(), Data, KeyIdx);
                Value *KeyChar = IRB_B.CreateLoad(IRB_B.getInt8Ty(), KeyCharPtr);

                Value *DecChar = IRB_B.CreateXor(EncChar, KeyChar);
                Value *DecCharPtr = IRB_B.CreateInBoundsGEP(IRB_B.getInt8Ty(), OutBuf, iValue);
                IRB_B.CreateStore(DecChar, DecCharPtr);

                // In the body of the loop, increase the value of i
                IRB_B.CreateStore(IRB_B.CreateAdd(iValue, IRB_B.getInt32(1)), i);

                IRB_B.CreateBr(loopCondBlock);
                IRB_B.SetInsertPoint(loopEndBlock);
            }

            BasicBlock *C = BasicBlock::Create(F.getContext(), "StoreStringDecBB", &F, D);
            IRB_B.CreateBr(C);
            IRB_B.SetInsertPoint(C);

            // Atomically add StoreInst at the beginning of C Whether the control flow comes from A or B,
            // the global variables (GVs) must be decrypted.
            StoreInst *SI = IRB_B.CreateStore(ConstantInt::get(Type::getInt32Ty(F.getContext()), 1), StatusGV);
            SI->setAlignment(Align(4));
            SI->setAtomic(AtomicOrdering::Release); // Release the lock obtained in LI

            IRB_B.CreateBr(D);

            IRBuilder<> IRB_D(D->getFirstNonPHIOrDbgOrLifetime());

            ConstantStringPool.clear();
            Changed |= true;
        }

        return Changed;

        std::set<GlobalVariable *> ConstantStringUsers;
        // collect all c strings
        for (GlobalVariable &GV : M.globals()) {
            if (!GV.isConstant() || !GV.hasInitializer() || GV.hasDLLExportStorageClass() || GV.isDLLImportDependent()) {
                continue;
            }
            if (GV.isNullValue() || GV.isZeroValue()) {
                continue;
            }
            if (GV.getName().startswith("rise_"))
                continue;
            Constant *Init = GV.getInitializer();
            if (Init == nullptr)
                continue;

            if (ConstantDataSequential *CDS = dyn_cast<ConstantDataSequential>(Init)) {
                if (isCString(CDS)) {
                    StringRef Data = CDS->getRawDataValues();
                    std::shared_ptr<CSPEntry> Entry = std::make_shared<CSPEntry>();
                    Entry->ID = static_cast<unsigned>(ConstantStringPool.size());
                    Entry->Salt = cryptoutils->get_range(0xffffffff);
                    Entry->EncKeySize = cryptoutils->get_range(8, 32);
                    Entry->EncKey.resize(Entry->EncKeySize);
                    std::generate(std::begin(Entry->EncKey), std::end(Entry->EncKey),
                                  []() { return cryptoutils->get_range(1, std::numeric_limits<uint8_t>::max()); });
                    Entry->EncData.reserve(Data.size());
                    for (unsigned I = 0; I < Data.size(); ++I) {
                        Entry->EncData.push_back(static_cast<uint8_t>(Data[I] ^ Entry->EncKey[I % Entry->EncKeySize]));
                    }
                    ConstantAggregateZero *ZeroInit = ConstantAggregateZero::get(CDS->getType());
                    string DecName =
                        formatv("rise_dec_{0}_{1}_{2}", GV.getName(), Twine::utohexstr(Entry->ID), Twine::utohexstr(Entry->Salt));
                    GlobalVariable *DecGV = new GlobalVariable(M, CDS->getType(), false, GlobalValue::PrivateLinkage, ZeroInit, DecName);
                    string DecStatusName =
                        formatv("rise_dec_status_{0}_{1}_{2}", GV.getName(), Twine::utohexstr(Entry->ID), Twine::utohexstr(Entry->Salt));
                    GlobalVariable *DecStatus =
                        new GlobalVariable(M, Type::getInt32Ty(Ctx), false, GlobalValue::PrivateLinkage, Zero, DecStatusName);
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
        for (std::shared_ptr<CSPEntry> Entry : ConstantStringPool) {
            Entry->DecFunc = buildDecryptFunction(&M, Entry);
        }

        // build initialization function for supported constant string users
        for (GlobalVariable *GV : ConstantStringUsers) {
            if (isValidToEncrypt(GV)) {
                Type *EltType = GV->getValueType();
                ConstantAggregateZero *ZeroInit = ConstantAggregateZero::get(EltType);
                GlobalVariable *DecGV =
                    new GlobalVariable(M, EltType, false, GlobalValue::PrivateLinkage, ZeroInit, "rise_dec_" + GV->getName());
                DecGV->setAlignment(MaybeAlign(GV->getAlignment()));
                GlobalVariable *DecStatus = new GlobalVariable(M, Type::getInt32Ty(Ctx), false, GlobalValue::PrivateLinkage, Zero,
                                                               "rise_dec_status_" + GV->getName());
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
        for (std::shared_ptr<CSPEntry> Entry : ConstantStringPool) {
            Data.clear();
            JunkBytes.clear();
            getRandomBytes(JunkBytes, 4, 16);
            Data.insert(Data.end(), JunkBytes.begin(), JunkBytes.end());
            Entry->Offset = static_cast<unsigned>(Data.size());
            Data.insert(Data.end(), Entry->EncKey.begin(), Entry->EncKey.end());
            Data.insert(Data.end(), Entry->EncData.begin(), Entry->EncData.end());
            JunkBytes.clear();
            getRandomBytes(JunkBytes, 4, 16);
            Data.insert(Data.end(), JunkBytes.begin(), JunkBytes.end());
            Constant *CDA = ConstantDataArray::get(Ctx, ArrayRef<uint8_t>(Data));
            string encStringName = formatv("rise_encrypted_string_{0}_{1}", Twine::utohexstr(Entry->ID), Twine::utohexstr(Entry->Salt));
            Entry->EncryptedStringTable = new GlobalVariable(M, CDA->getType(), true, GlobalValue::PrivateLinkage, CDA, encStringName);
        }

        // Constant *CDA =
        //     ConstantDataArray::get(Ctx, ArrayRef<uint8_t>(Data));
        // EncryptedStringTable =
        //     new GlobalVariable(M, CDA->getType(), true,
        //     GlobalValue::PrivateLinkage,
        //                        CDA, "EncryptedStringTable");

        // decrypt string back at every use, change the plain string use to the decrypted one
        for (Function &F : M) {
            if (F.isDeclaration())
                continue;
            if (function_obf_map[F.getName().str()])
                continue;
            Changed |= processConstantStringUse(&F);
        }

        for (auto &I : CSUserMap) {
            CSUser *User = I.second;
            if (function_obf_map[User->InitFunc->getName().str()])
                continue;
            Changed |= processConstantStringUse(User->InitFunc);
        }

        // delete unused global variables
        deleteUnusedGlobalVariable();
        for (std::shared_ptr<CSPEntry> Entry : ConstantStringPool) {
            if (Entry->DecFunc->use_empty()) {
                Entry->DecFunc->eraseFromParent();
                Entry->DecGV->eraseFromParent();
                Entry->DecStatus->eraseFromParent();
                Entry->EncryptedStringTable->eraseFromParent();
            }
        }
        return Changed;
    }
    void collectConstantStringUser(GlobalVariable *CString, std::set<GlobalVariable *> &Users) {
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
        if (!GV->hasInitializer()) {
            return false;
        }
        if (GV->isConstant()) {
            return true;
        } else if (isCFConstantStringTag(GV) || isObjCSelectorPtr(GV)) {
            return true;
        }
        return false;
    }

    bool processConstantStringUse(Function *F) {
        if (!toObfuscate(Flag, F, "strobf")) {
            errs() << "StringObfuscation off, fun: " << demangle(F->getName().str()) << ", flag: " << this->Flag << "\n";
            return false;
        }
        if (!toObfuscateUint32Option(F, "strobf_prob", &ElementObfuscationProbTemp))
            ElementObfuscationProbTemp = ElementObfuscationProb;

        // Check if the number of applications is correct
        if (!((ElementObfuscationProbTemp > 0) && (ElementObfuscationProbTemp <= 100))) {
            errs() << "StringObfuscation application element percentage "
                      "-strobf_prob=x must be 0 < x <= 100\n";
            return false;
        }
        uint32_t ProbTemp = cryptoutils->get_range(100);
        if (ProbTemp > ElementObfuscationProbTemp) {
            errs() << "StringObfuscation off, fun: " << demangle(F->getName().str()) << ", " << ProbTemp
                   << "<=" << ElementObfuscationProbTemp << "\n";
            return false;
        }
        LowerConstantExpr(*F);
        SmallPtrSet<GlobalVariable *, 16> DecryptedGV; // if GV has multiple use in a block, decrypt only at the
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
                    for (unsigned int I = 0; I < PHI->getNumIncomingValues(); ++I) {
                        if (GlobalVariable *GV = dyn_cast<GlobalVariable>(PHI->getIncomingValue(I))) {
                            auto Iter1 = CSPEntryMap.find(GV);
                            auto Iter2 = CSUserMap.find(GV);
                            if (Iter2 != CSUserMap.end()) { // GV is a constant string user
                                CSUser *User = Iter2->second;
                                if (DecryptedGV.count(GV) > 0) {
                                    Inst.replaceUsesOfWith(GV, User->DecGV);
                                } else {
                                    Instruction *InsertPoint = PHI->getIncomingBlock(I)->getTerminator();
                                    IRBuilder<> IRB(InsertPoint);
                                    IRB.CreateCall(User->InitFunc, {User->DecGV});
                                    Inst.replaceUsesOfWith(GV, User->DecGV);
                                    MaybeDeadGlobalVars.insert(GV);
                                    DecryptedGV.insert(GV);
                                    Changed = true;
                                }
                            } else if (Iter1 != CSPEntryMap.end()) { // GV is a constant string
                                std::shared_ptr<CSPEntry> Entry = Iter1->second;
                                if (DecryptedGV.count(GV) > 0) {
                                    Inst.replaceUsesOfWith(GV, Entry->DecGV);
                                } else {
                                    Instruction *InsertPoint = PHI->getIncomingBlock(I)->getTerminator();
                                    IRBuilder<> IRB(InsertPoint);

                                    Value *OutBuf = IRB.CreateBitCast(Entry->DecGV, IRB.getInt8PtrTy());
                                    Value *Data =
                                        IRB.CreateInBoundsGEP(Entry->EncryptedStringTable->getValueType(), Entry->EncryptedStringTable,
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
                    for (User::op_iterator Op = Inst.op_begin(); Op != Inst.op_end(); ++Op) {
                        if (GlobalVariable *GV = dyn_cast<GlobalVariable>(*Op)) {
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
                                std::shared_ptr<CSPEntry> Entry = Iter1->second;
                                if (DecryptedGV.count(GV) > 0) {
                                    Inst.replaceUsesOfWith(GV, Entry->DecGV);
                                } else {
                                    IRBuilder<> IRB(&Inst);

                                    Value *OutBuf = IRB.CreateBitCast(Entry->DecGV, IRB.getInt8PtrTy());
                                    Value *Data =
                                        IRB.CreateInBoundsGEP(Entry->EncryptedStringTable->getValueType(), Entry->EncryptedStringTable,
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

    bool isCString(const ConstantDataSequential *CDS) {
        // isString
        if (!isa<ArrayType>(CDS->getType()))
            return false;
        if (!CDS->getElementType()->isIntegerTy(8) && !CDS->getElementType()->isIntegerTy(16) && !CDS->getElementType()->isIntegerTy(32))
            return false;

        for (unsigned i = 0, e = CDS->getNumElements(); i != e; ++i) {
            uint64_t Elt = CDS->getElementAsInteger(i);
            if (Elt == 0) {
                return i == (e - 1); // last element is null
            }
        }
        return false; // null not found
    }
    bool isObjCSelectorPtr(const GlobalVariable *GV) {
        return GV->isExternallyInitialized() && GV->hasLocalLinkage() && GV->getName().startswith("OBJC_SELECTOR_REFERENCES_");
    }

    bool isCFConstantStringTag(const GlobalVariable *GV) {
        const Constant *Init = GV->getInitializer();
        if (Init == nullptr)
            return false;
        if (GV->getSection().startswith("llvm.")) {
            return false;
        }
        if (const ConstantDataSequential *CDS = dyn_cast<ConstantDataSequential>(Init)) {
            Type *ETy = CDS->getElementType();
            return ETy->isStructTy() && ETy->getStructName() == "struct.__NSConstantString_tag";
        }
        return false;
    }

    void deleteUnusedGlobalVariable() {
        bool Changed = true;
        while (Changed) {
            Changed = false;
            for (auto Iter = MaybeDeadGlobalVars.begin(); Iter != MaybeDeadGlobalVars.end();) {
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

    Function *buildDecryptFunction(Module *M, const std::shared_ptr<CSPEntry> Entry) {
        LLVMContext &Ctx = M->getContext();
        IRBuilder<> IRB(Ctx);
        FunctionType *FuncTy = FunctionType::get(Type::getVoidTy(Ctx), {Type::getInt8PtrTy(Ctx), Type::getInt8PtrTy(Ctx)}, false);
        string FuncName = formatv("rise_decrypt_fun_{0}_{1}", Twine::utohexstr(Entry->ID), Twine::utohexstr(Entry->Salt));
        FunctionCallee Callee = M->getOrInsertFunction(FuncName, FuncTy);
        Function *DecFunc = cast<Function>(Callee.getCallee());
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
        BasicBlock *UpdateDecStatus = BasicBlock::Create(Ctx, "UpdateDecStatus", DecFunc);
        BasicBlock *Exit = BasicBlock::Create(Ctx, "Exit", DecFunc);

        IRB.SetInsertPoint(Enter);
        ConstantInt *KeySize = ConstantInt::get(Type::getInt32Ty(Ctx), Entry->EncKey.size());
        Value *EncPtr = IRB.CreateInBoundsGEP(IRB.getInt8Ty(), Data, KeySize);
        Value *DecStatus = IRB.CreateLoad(Entry->DecStatus->getValueType(), Entry->DecStatus);
        Value *IsDecrypted = IRB.CreateICmpEQ(DecStatus, IRB.getInt32(1));
        IRB.CreateCondBr(IsDecrypted, Exit, LoopBody);

        IRB.SetInsertPoint(LoopBody);
        PHINode *LoopCounter = IRB.CreatePHI(IRB.getInt32Ty(), 2);
        LoopCounter->addIncoming(IRB.getInt32(0), Enter);

        Value *EncCharPtr = IRB.CreateInBoundsGEP(IRB.getInt8Ty(), EncPtr, LoopCounter);
        Value *EncChar = IRB.CreateLoad(IRB.getInt8Ty(), EncCharPtr);
        Value *KeyIdx = IRB.CreateURem(LoopCounter, KeySize);

        Value *KeyCharPtr = IRB.CreateInBoundsGEP(IRB.getInt8Ty(), Data, KeyIdx);
        Value *KeyChar = IRB.CreateLoad(IRB.getInt8Ty(), KeyCharPtr);

        Value *DecChar = IRB.CreateXor(EncChar, KeyChar);
        Value *DecCharPtr = IRB.CreateInBoundsGEP(IRB.getInt8Ty(), PlainString, LoopCounter);
        IRB.CreateStore(DecChar, DecCharPtr);

        Value *NewCounter = IRB.CreateAdd(LoopCounter, IRB.getInt32(1), "", true, true);
        LoopCounter->addIncoming(NewCounter, LoopBody);

        Value *Cond = IRB.CreateICmpEQ(NewCounter, IRB.getInt32(static_cast<uint32_t>(Entry->EncData.size())));
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
        FunctionType *FuncTy = FunctionType::get(Type::getVoidTy(Ctx), {User->DecGV->getType()}, false);
        Function *InitFunc =
            Function::Create(FuncTy, GlobalValue::PrivateLinkage, "__global_variable_initializer_" + User->GV->getName(), M);

        auto ArgIt = InitFunc->arg_begin();
        Argument *Thiz = ArgIt;

        Thiz->setName("this");
        Thiz->addAttr(Attribute::NoCapture);

        // convert constant initializer into a series of instructions
        BasicBlock *Enter = BasicBlock::Create(Ctx, "Enter", InitFunc);
        BasicBlock *InitBlock = BasicBlock::Create(Ctx, "InitBlock", InitFunc);
        BasicBlock *Exit = BasicBlock::Create(Ctx, "Exit", InitFunc);

        IRB.SetInsertPoint(Enter);
        Value *DecStatus = IRB.CreateLoad(User->DecStatus->getValueType(), User->DecStatus);
        Value *IsDecrypted = IRB.CreateICmpEQ(DecStatus, IRB.getInt32(1));
        IRB.CreateCondBr(IsDecrypted, Exit, InitBlock);

        IRB.SetInsertPoint(InitBlock);
        Constant *Init = User->GV->getInitializer();
        lowerGlobalConstant(Init, IRB, User->DecGV, User->Ty);

        if (isObjCSelectorPtr(User->GV)) {
            // resolve selector
            FunctionCallee callee =
                M->getOrInsertFunction("sel_registerName", FunctionType::get(IRB.getInt8PtrTy(), {IRB.getInt8PtrTy()}, false));
            Function *sel_registerName = cast<Function>(callee.getCallee());
            Value *Selector = IRB.CreateCall(sel_registerName, {Init});
            IRB.CreateStore(Selector, User->DecGV);
        }

        IRB.CreateStore(IRB.getInt32(1), User->DecStatus);
        IRB.CreateBr(Exit);

        IRB.SetInsertPoint(Exit);
        IRB.CreateRetVoid();
        return InitFunc;
    }

    void getRandomBytes(std::vector<uint8_t> &Bytes, uint32_t MinSize, uint32_t MaxSize) {
        uint32_t N = cryptoutils->get_uint32_t();
        uint32_t Len;

        assert(MaxSize >= MinSize);

        if (MinSize == MaxSize) {
            Len = MinSize;
        } else {
            Len = MinSize + (N % (MaxSize - MinSize));
        }

        Bytes.resize(Len);
        for (uint32_t i = 0; i < Len; i++) {
            Bytes[i] = cryptoutils->get<uint8_t>();
        }
    }
    void getRandomBytes(std::vector<uint16_t> &Bytes, uint32_t MinSize, uint32_t MaxSize) {
        uint32_t N = cryptoutils->get_uint32_t();
        uint32_t Len;

        assert(MaxSize >= MinSize);

        if (MinSize == MaxSize) {
            Len = MinSize;
        } else {
            Len = MinSize + (N % (MaxSize - MinSize));
        }

        Bytes.resize(Len);
        for (uint32_t i = 0; i < Len; i++) {
            Bytes[i] = cryptoutils->get<uint16_t>();
        }
    }
    void getRandomBytes(std::vector<uint32_t> &Bytes, uint32_t MinSize, uint32_t MaxSize) {
        uint32_t N = cryptoutils->get_uint32_t();
        uint32_t Len;

        assert(MaxSize >= MinSize);

        if (MinSize == MaxSize) {
            Len = MinSize;
        } else {
            Len = MinSize + (N % (MaxSize - MinSize));
        }

        Bytes.resize(Len);
        for (uint32_t i = 0; i < Len; i++) {
            Bytes[i] = cryptoutils->get<uint32_t>();
        }
    }
    void lowerGlobalConstant(Constant *CV, IRBuilder<> &IRB, Value *Ptr, Type *Ty) {
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
    void lowerGlobalConstantStruct(ConstantStruct *CS, IRBuilder<> &IRB, Value *Ptr, Type *Ty) {
        for (unsigned I = 0, E = CS->getNumOperands(); I != E; ++I) {
            Constant *CV = CS->getOperand(I);
            Value *GEP = IRB.CreateGEP(Ty, Ptr, {IRB.getInt32(0), IRB.getInt32(I)});
            lowerGlobalConstant(CV, IRB, GEP, CV->getType());
        }
    };
    void lowerGlobalConstantArray(ConstantArray *CA, IRBuilder<> &IRB, Value *Ptr, Type *Ty) {
        for (unsigned I = 0, E = CA->getNumOperands(); I != E; ++I) {
            Constant *CV = CA->getOperand(I);
            Value *GEP = IRB.CreateGEP(Ty, Ptr, {IRB.getInt32(0), IRB.getInt32(I)});
            lowerGlobalConstant(CV, IRB, GEP, CV->getType());
        }
    }
};
} // namespace llvm

// Create string obfuscation pass
ModulePass *llvm::createStringObfuscation() { return new StringObfuscation(); }
ModulePass *llvm::createStringObfuscation(bool Flag) { return new StringObfuscation(Flag); }
char StringObfuscation::ID = 0;
INITIALIZE_PASS(StringObfuscation, "strobf", "Enable String Obfuscation", false, false)
