# CmpMap Test SUT

This test SUT performs a series of comparisons that create CmpLog entries for validating the cmplog map contents

## Compilation

For Cmplog, you need a recent LLVM and afl-clang-fast that supports CmpLog instrumentation.

Build with `CC=afl-clang-fast make`