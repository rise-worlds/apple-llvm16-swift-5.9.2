// For open-source license, please refer to
// [License](https://github.com/HikariObfuscator/Hikari/wiki/License).
//===----------------------------------------------------------------------===//
#include "llvm/Transforms/Obfuscation/CryptoUtils.h"
#include "llvm/Support/Format.h"
#include "llvm/Support/raw_ostream.h"
#include <chrono>

using namespace llvm;
namespace llvm {
ManagedStatic<CryptoUtils> cryptoutils;
}
CryptoUtils::CryptoUtils() {}

uint32_t
CryptoUtils::scramble32(uint32_t in,
                        std::map<uint32_t /*IDX*/, uint32_t /*VAL*/> &VMap) {
  if (VMap.find(in) == VMap.end()) {
    uint32_t V = get_uint32_t();
    VMap[in] = V;
    return V;
  } else {
    return VMap[in];
  }
}
CryptoUtils::~CryptoUtils() {
  if (eng != nullptr)
    delete eng;
}
void CryptoUtils::prng_seed() {
  using namespace std::chrono;
  std::uint_fast64_t ms =
      duration_cast<milliseconds>(system_clock::now().time_since_epoch())
          .count();
  errs() << format("std::mt19937_64 seeded with current timestamp: %" PRIu64 "",
                   ms)
         << "\n";
  eng = new std::mt19937_64(ms);
}
void CryptoUtils::prng_seed(std::uint_fast64_t seed) {
  errs() << format("std::mt19937_64 seeded with: %" PRIu64 "", seed) << "\n";
  eng = new std::mt19937_64(seed);
}
std::uint_fast64_t CryptoUtils::get_raw() {
  if (eng == nullptr)
    prng_seed();
  return (*eng)();
}
uint64_t CryptoUtils::get_range(uint64_t min, uint64_t max) {
  if (max == 0)
    return 0;
  std::uniform_int_distribution<uint64_t> dis(min, max - 1);
  return dis(*eng);
}
void CryptoUtils::get_bytes(char* buffer, const int len) {
  if (eng == nullptr)
    prng_seed();
  assert(buffer != nullptr && "CryptoUtils::get_bytes buffer=nullptr");
  assert(len > 0 && "CryptoUtils::get_bytes len <= 0");

  for (size_t i = 0; i < len; i++) {
    buffer[i] = get<char>();
  }
}