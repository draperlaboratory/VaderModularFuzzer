# VMF libFuzzer-style harness driver

## Overview
The provided library `libVMFDriver.a` lets VMF use libFuzzer-style harnesses that 
implement `LLVMFuzzerTestOneInput()`. It implements the AFL++ shared-memory test case
delivery method and "persistent mode" execution with deferred initialization. See the 
[Persistent Mode](/docs/fuzz_harnessing.md#persistent-mode) 
section of the VMF harnessing guide for more details.

To use, the harness must be compiled with `afl-clang-fast` or `afl-clang-lto`. 
The VMF driver library is linked in with the fuzz harness:
```bash
$ afl-clang-fast -o harness fuzz_harness.c ${VMF_INSTALL_DIR}/lib/libVMFDriver.a
```
A sample fuzz harness that implements the libFuzzer-style interface is provided in `harness_example.c`

## Runtime options
The number of "persistent mode" executions before the process is respawned can
be controlled using the `-n` parameter. A VMF configuration file would use the following:
```yaml
AFLForkserverExecutor:
  sutArgv: [ "harness", "-n", "10000" ]
```

The driver itself implements a test mode that can run individual test cases from the
command line: 
```bash
$ ./harness -f <testcase_file>
```

Several behaviors are controllable through environment variables:
* `AFL_FUZZER_LOOPCOUNT`: Specify the number of "persistent mode" executions before the 
process is respawned. This environment variable will override the `-n` command-line parameter.
* `VMF_DRIVER_STDERR_DUPLICATE_FILENAME`: Duplicate stderr to the specified file
* `VMF_DRIVER_CLOSE_FD_MASK`: Close stdout if the value is 0x01. Close stderr if the value 
is 0x02. Close both if the value is 0x03.
