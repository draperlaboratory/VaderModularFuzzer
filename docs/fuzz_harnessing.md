# Fuzz Harnessing

**For the purposes of getting started, the most important component is the "fuzz harness." All other components have sane defaults for the most common fuzzing paradigms.**

## Harnessing a System Under Test (SUT)

Simplistically, the "fuzzing software" (e.g. VMF) provides test cases.  The "fuzz harness" must provide a way to run the SUT, a way to feed it test cases, and a way to retrieve the test results for analysis by the fuzzing software.  

The "fuzz harness" is responsible for:

- managing the lifecycle of the SUT (e.g. starting and resetting for each new testcases)
- inputting test cases from the fuzzing software into the SUT
- returning data from the SUT to the fuzzing software (e.g. code coverage, exit status, ...)

An interesting aspect of common fuzz harness implementations that often confuses the meaning of a "fuzz harness" is that the fuzz harness may be either external to the SUT or compiled into the SUT itself.

### Example A: Basic Forkserver (eg classic native AFL++ harnessing)
![Example A Diagram](./img/VaderOverview_7.png)

 _Example A)_ the default AFL fuzz harness is when the SUT is hardcoded to read input from either a file or stdin. Then, the SUT is compiled using the AFL compiler, which adds instrumentation that manages the lifecycle of the SUT (see forkserver), tracks and returns code coverage as a bitmap to the fuzzing software. In this case the fuzz harness' responsibilities are implemented both in the SUT itself and by instrumentation that is compiled into the SUT. The runtime is native (non-emulated) execution.

 ***Note: VMF currently uses only this kind of fuzz harness (via our AFLForkserverExecutor Module)***

### Example B: Execution in Emulated Environment (eg QEMU AFL, AFL Unicorn)
![Example B Diagram](./img/VaderOverview_8.png)

_Example B)_ AFL unicorn enables fuzzing non-native SUTs without source code. In this case, the SUT's runtime is the unicorn emulation environment. Because the SUT is a binary (or memory snapshot), the instrumentation cannot be compiled in. Instead, unicorn's hooking framework is used to implement the fuzz harness. Hooks must be defined to manage the SUT's lifecycle by setting up and resetting state between fuzz testcases, inject fuzzed input in memory to be evaluated, and capture and return code coverage.

### Example C: Function Call (eg libFuzzer)
![Example C Diagram](./img/VaderOverview_9.png)

_Example C)_ In libFuzzer-style fuzzing, all of the harness' responsibilities are implemented in a single file, colloquially referred to as "the harness." The user overloads the "LLVMFuzzerTestOneInput" function (see below) to pass data to the SUT, and that function is called for each testcase. Code coverage instrumentation and feedback to the fuzzing software is implemented as a compiler pass when this "harness" is compiled into the SUT.

```c
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
```

## AFL++ Style Harnessing

### Basic file I/O + Forkserver
The simplest way to prepare an AFL++ style harness is by creating a program thats reads testcase contents via a file input or stdin, and then invokes the target code with the provided input. The SUT must be compiled with the AFL++ compiler ([available here](https://github.com/AFLplusplus/AFLplusplus)), but does not otherwise need any additional configuration options.

The provided [haystack example](../test/haystackSUT/haystack.c) illustrates a harness of this kind. Observe how `main` reads input data and then calls the target `check` function using that data.

Compile this code using the AFL compiler like so:

```bash
cd vmf_install/test/haystackSUT
afl-clang-fast -o haystack haystack.c
cd ../..
```

When harnessed this way, the fuzzer will fork a new process for each testcase input and run that testcase in its own process. This method is the most robust and general-purpose, but is also slow because a new process must be created for each testcase.

All else being equal, stdin is preferred over file I/O because it is faster.

### Persistent Mode
Persistent mode is a harnessing technique where multiple testcases are run in the same process without exiting after each testcase. It can be drastically faster than the basic forkserver method because the cost of the `fork` is removed from the critical fuzzing loop. To use AFL++'s persistent mode, simply add a `while (__AFL_LOOP(10000))` loop around the target code; a new testcase will be delivered at the beginning of the loop, and the coverage and execution result will be returned to the fuzzer at the end of the loop. See the [haystack persistent example](../test/haystackSUT/haystack_AFL_persist.c) for an example persistent harness and the [AFL++ persistent mode documentation.](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.persistent_mode.md)

The number in the loop (10,000 in this example) indicates the total number of testcases that should be run before requesting a new process, which is done periodically to prevent leftover state from building up too much.

There are no additional compiler flags required to compile a persistent harness: the only requirement is the addition of the `__AFL_LOOP`. Use the following to compile the haystack persistent mode example:
```bash
cd vmf_install/test/haystackSUT
afl-clang-fast -o haystack_AFL_persist haystack_AFL_persist.c
cd ../..
```

There are also no additional flags or settings required to use a persistent harness. The persistent harness is detected automatically by the fuzzer (either VMF or AFL++) and enabled. You can see in the `haystack_AFL_persist.yaml` config file that no persistent-specific parameters are set.

Run the persistent haystack example with:
```bash
./bin/vader -c test/haystackSUT/haystack_AFL_persist.yaml -c test/config/basicModules.yaml
```

You should see a large increase in executions per second compared to the non-persistent haystack.

**Note that peristent mode is not appropriate in all SUTs!** It requires the SUT behave properly when restarted repeatedly inside the persistent loop, which is a big assumption. Always test your harness in non-persistent mode first and compare its behavior to the persistent version.

Note the following limitations and warnings:
- Persistent mode harnesses should be made as side-effect free as possible. For example, memory allocations that are not freed cause memory leaks, which can eventually cause memory limit problems that can be hard to reproduce. Reducing the number of executions per process can help.
- Calls that drastically effect state (eg `exit`) should be avoided. A SUT that calls `exit` inside the persistent loop will only run once per testcase, effectively becoming non-persistent. Calls to `open` that are not closed on each execution can cause file descriptor leaks, etc.
- Logic bugs can be introduced by not properly resetting state. State should be reset at the beginning of the persistent loop (eg zero out input buffers, reset variables as needed by the SUT).
- When reading testcases from files, the descriptor should be closed and opened inside the persistent loop.
- You may need to turn off compiler optimizations, see included haystack persistent example for how this is done
- The number of coverage bytes may differ somewhat in persistent mode compared to the basic forkserver model. This is because the feedback data (eg code coverage) is reset at the beginning of the persistent loop and only reflects what is inside the persistent loop.
- You may use `while (__AFL_LOOP(UINT_MAX))` if you are sure there is no state to cleanup and you want to avoid forking entirely. Use cautiously.
- If a high percent of executions produce crashes, the benefit of persistent mode will be reduced. Each crash causes a new process to be forked.

Persistent mode is logically separate from Deferred Initialization and Shared Memory Fuzzing, and may be used standalone or may be combined with either. Shared Memory Fuzzing, however, requires a Persistent Mode harness.

### Deferred Initialization
A forkserver begins executing each testcase at the *fork point* in the SUT. By default, the fork point is placed at the top of `main`, which means that the SUT begins executing each testcase from the top of `main`.

In some cases, we may want to move the fork point closer to the code that is actually being tested. This can improve fuzzing speed. For example, if there is expensive initialization logic that does not depend on the input data, it can safely be run in the parent prior to each fork and thus be removed from the critical fuzzing loop.

To use Deferred Initialization, place a call to ` __AFL_INIT()` in the SUT where you could like to set the fork point. This call changes where the forkserver initialization is added into the SUT and thus where each child forks from the parent process.

To illustrate, look at the [haystack deferred initialization example](../test/haystackSUT/haystack_AFL_deferred.c). This SUT is a modified version of haystack where a sleep for 100 milliseconds is added to the top of the `main` function. This sleep represents expensive initialization work, and will cause the fuzzing speed to drop to a slow 10 per second. An `__AFL_INIT()` call is placed after the sleep, marking where we would like fuzzing to begin to remove the expensive sleep from the fuzzing loop.

There are no additional compiler flags required to compile a harness with deferred initialization: the only requirement is the addition of the `__AFL_INIT()` call. Use the following to compile the deferred execution example:
```bash
cd vmf_install/test/haystackSUT
afl-clang-fast -o haystack_AFL_deferred haystack_AFL_deferred.c
cd ../..
```

There are also no additional flags or settings required to use a deferred initialization harness. The deferred initialization is detected automatically by the fuzzer (either VMF or AFL++) and enabled. You can see in the `haystack_AFL_deferred.yaml` config file that no deferred initialization specific parameters are set.

Run the deferred haystack example with:
```bash
./bin/vader -c test/haystackSUT/haystack_AFL_deferred.yaml -c test/config/basicModules.yaml
```

You should see an execution speed comparable to what you get with `haystack_file.yaml`. Try removing the `__AFL_INIT()` from the SUT, thus moving the forkpoint back to `main`, and compiling again. You should see a drastic decrease in performance as the sleep is once again included in the criticial fuzzing loop and the benefits of Deferred Initialization are removed.

Deferred Initialization is logically separate from Persistent Mode and Shared Memory Fuzzing, and may be used standalone or may be mixed-and-matched with either of them.

### Shared Memory Fuzzing
Sending testcase data via shared memory instead of files or I/O can further improve performace. This technique is called in-memory or shared memory fuzzing and is faster because the overhead cost of I/O is removed from the fuzzing loop.

To use shared memory fuzzing, add a call to `__AFL_FUZZ_INIT()` in the harness after other includes but outside of other functions. See the [haystack shared memory example](../test/haystackSUT/haystack_AFL_shmem.c)

When this call is included, the `__AFL_FUZZ_TESTCASE_BUF` is defined and has the `char *` type. It points to the testcase data in the shared memory region and can be used by the program in place of reading that data via files or stdin. The `__AFL_FUZZ_TESTCASE_LEN` symbol is also defined, has an `int` type, and contains the number of bytes of data that are held in the shared memory region.

They can be used like so:
```c
unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;
int len = __AFL_FUZZ_TESTCASE_LEN;
```

If shared memory fuzzing is used in combination with deferred initialization, these lines should be placed *after* `__AFL_INIT()`.

No special compilation flags or VMF config options need to be set to use a shared memory SUT. The feature is detected and used automatically.

The shared memory example can be run with:

```bash
./bin/vader -c test/haystackSUT/haystack_AFL_shmem.yaml -c test/config/basicModules.yaml
```

Note the further improvement in exec/s compared to just persistent mode alone. 

Also note that a maximum testcase size of 1MB is enforced when using shared memory fuzzing.

Shared memory fuzzing requires a Persistent Mode harness and so must be used in combination with Persistent Mode. It is independent from Deferred Initialization.

## Windows LibFuzzer for Frida Harnessing

There are two ways to build a SUT for use with the VMF FridaRE windows run-time. 
    - Create an executable using the vmf frida rtlib
    - Create a DLL that exports a LLVMFuzzerTestOneInput export. 

### Build Windows executable

```powershell
set VMF=<location of built vmf_install>
cd test/haystackSUT
cl /MD haystack_libfuzzer.c %VMF%\lib\vmf_frida_rtlib.lib %VMF%\lib\vmf_frida_rtembed.lib shell32.lib /link /subsystem:console
cd ../..
```

*note: if the vmf_install is a debug configuration, use /MDd* 

### Build Windows DLL 

```powershell
set VMF=<location of built vmf_install>
cd test/haystackSUT
cl /MD /DMAKE_DLL /LD haystack_libfuzzer.c
cd ../..
```
