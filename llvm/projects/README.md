# 花火 适配Xcode 14和Apple Silicon Mac
将使用substitute改为使用[Dobby](https://github.com/jmpews/Dobby)

增加了New Pass Manager的Hook

LLVM Pass可以从[https://github.com/61bcdefg/Hikari-LLVM15-Core](https://github.com/61bcdefg/Hikari-LLVM15-Core) [https://github.com/61bcdefg/Hikari-LLVM15-Headers](https://github.com/61bcdefg/Hikari-LLVM15-Headers)获取，移植到对应的swift llvm再配合这个仓库编译即可

## 已知问题

### ld: Assertion failed: (dylib != NULL), function classicOrdinalForProxy, file LinkEditClassic.hpp, line 495.

解决方法： 在Other C Flags加上`-fno-objc-msgsend-selector-stubs`

# 花火
Hassle-free Obfuscator-Enabled Apple Clang without any sort of compromise.

![Demo](https://github.com/HikariObfuscator/Hanabi/blob/master/Demo.jpg?raw=true)

# License
Please refer to [License](https://github.com/HikariObfuscator/Hikari/wiki/License).

Note that this linked version of license text overrides any artifact left in source code

# Must be this tall to ride
Due to its hackish nature (Which is why I don't want to do this in the first place), you should probably know some LLVM/macOS Hooking/Binary Patching and stuff to debug this thing

## Obtaining Source
- ``git clone https://github.com/rise-worlds/apple-llvm.git ``

## Build
```bash
cmake -S llvm -DCMAKE_BUILD_TYPE=Release -DLLVM_ABI_BREAKING_CHECKS=FORCE_OFF -G Ninja -B build
cmake --build build --target LLVMHanabi
cp build/lib/libLLVMHanabiDeps.dylib /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/
cp build/lib/libLLVMHanabi.dylib /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/
```

# Patching

You need to build ``https://github.com/alexzielenski/optool`` and put it in your $PATH, then you need to patch two libraries into Clang/SwiftC.
**!!!ORDER IS VERY IMPORTANT!!!**
- ``sudo optool install -c load -p @executable_path/libLLVMHanabi.dylib -t /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang``
- ``sudo codesign -fs - /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang``
- ``sudo optool install -c load -p @executable_path/libLLVMHanabi.dylib -t /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/swift-frontend``
- ``sudo codesign -fs - /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/swift-frontend``
***`swift-frontend` not support xcode 15+***

# How it works
- Strictly speaking, many changes are done to the Hikari Core to reduce LLVM library dependencies.
- Loader's linking options is modified to link to no LLVM library and fully resolve them at runtime in a flat namespace, this loader is also known as ``libLLVMHanabi.dylib``
- Then, we ship a custom mimimal subset of LLVM Core Libraries which serves as the fallback plan for symbols that are not exported in Apple's binaries, this is known as ``libLLVMHanabiDeps.dylib``.
- By not linking the full LLVM suite, we are allowed to reduce build time and more importantly, allows us to pass arguments like we normally would. (``-mllvm`` and ``-Xllvm``)


# Credits

- Thanks to [@AloneMonkey](https://github.com/AloneMonkey) for compiling substitute and ship it with his amazing project [MonkeyDev](https://github.com/AloneMonkey/MonkeyDev/blob/master/MFrameworks/libsubstitute.dylib)
- Thanks to [@UESTC-LXY](https://github.com/UESTC-LXY) for testing and discussion because I didn't bother to do so.
- Thanks to[@qokelate](https://github.com/qokelate) for initially discovering the broken CMake script and testing the new fix as well as suggestions to this README
- Thanks to [goron](https://github.com/amimo/goron)
