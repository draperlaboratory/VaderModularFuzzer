# Core Modules
This document provides more detailed documentation for the VMF Core Modules.

* [Core Module Overview](#core-module-overview)
* [AFLForkserverExecutor](#aflforkserverexecutor)
* [AFLFeedback and AFLFavoredFeedback](#aflfeedback-and-aflfavoredfeedback)
* [AFLMutators](#aflmutators)
* [ComputeStats](#computestats)
* [CorpusMinimization](#corpusminimization)
* [CSVMetadataOutput](#csvmetadataoutput)
* [Gramatron](#gramatron)
    + [Grammars](#grammars)
    + [Gramatron Modules](#gramatron-modules)
    + [Gramatron Usage](#gramatron-usage)
* [TrivialSeedInitialization](#trivialseedinitialization)
* [KleeInitialiation](#kleeinitialization)
* [LoggerMetadataOutput](#loggermetadataoutput)
* [MOPT](#mopt)
* [RedPawn](#redpawn)
* [StatsOutput](#statsoutput)
* [Controller Modules](#controller-modules)
    + [AnalysisController](#analysiscontroller)
    + [IterativeController](#iterativecontroller)
    + [NewCoverageController](#newcoveragecontroller)
    + [RunOnceController](#runoncecontroller)
* [Distributed Fuzzing Modules and Configuration Options](#distributed-fuzzing-modules-and-configuration-options)
    + [ServerSeedInitialization and ServerCorpusInitialization](#serverseedinitialization-and-servercorpusinitialization)
    + [ServerCorpusOutput](#servercorpusoutput)
    + [ServerCorpusMinOutput](#servercorpusminoutput)
    + [Parameters for Distributed Fuzzing](#parameters-for-distributed-fuzzing)



## Core Module Overview
The following core modules are provided along with VMF.  A brief summary of each module's function is provided below.

### Controller and Storage Modules

|Module Name|Type|Summary
| --------- | --- |------ |
|SimpleStorage|Storage|The default implementation of Storage|
|IterativeController|Controller|Controls a configurable set of modules to run a fuzzer|
|NewCoverageController|Controller|Supports toggling between input generation strategies when new coverage is found|
|RunOnceController|Controller|Runs every provided module exactly once before shutting down|

### Initialization Modules

|Module Name|Type|Summary
| --------- | --- |------ |
|DirectoryBasedSeedGen|Initialization|Creates initial test cases based on contents of a directory|
|GrammarBasedSeedGen|Initialization|Initialization module needed when using the Gramatron mutators|
|KleeInitialization|Initialization|Uses Klee to create initial test cases|
|ServerCorpusInitialization|Initialization|Used for distributed fuzzing to retrieve the whole CDMS corpus|
|ServerSeedInitialization|Initialization|Used for distributed fuzzing to retrieve the seeds, or recently minimized corpus from CDMS|
|StringsInitialization|Initialization|Uses the strings utility to create initial test cases|
|DictionaryInitialization|Initialization|Uses the strings utility to create a list that can be used to mutate test cases|
|TrivialSeedInitialization|Initialization|Creates initial test case of just "hello"|

### Input Generation and Mutator Modules

|Module Name|Type|Summary
| --------- | --- |------ |
|GeneticAlgorithmInputGenerator|InputGenerator|Manages mutators by selecting a base test and which mutators to mutate it with|
|MOPTInputGenerator|InputGenerator|Uses an optimized mutation algorithm to select mutators based on their prior performance|
|AFLFlipBitMutator|Mutator|Creates new test cases by flipping a random bit|
|AFLFlip2BitMutator|Mutator|Creates new test cases by flipping a pair of random bits|
|AFLFlip4BitMutator|Mutator|Creates new test cases by flipping a set of 4 random bits|
|AFLFlipByteMutator|Mutator|Creates new test cases by flipping a random byte|
|AFLFlip2ByteMutator|Mutator|Creates new test cases by flipping a random pair of bytes|
|AFLFlip4ByteMutator|Mutator|Creates new test cases by flipping a random set of 4 bytes|
|AFLRandomByteAddSubMutator|Mutator|Creates new test cases by adding and subtracting bounded random values to a random byte|
|AFLRandomByteMutator|Mutator|Creates new test cases by adding to a random byte|
|AFLDeleteMutator|Mutator|Creates new test cases by deleting a random chunk|
|AFLCloneMutator|Mutator|Creates new test cases by copying a random chunk|
|AFLSpliceMutator|Mutator|Creates new test cases by splicing two test cases together|
|GramatronGenerateMutator|Mutator|Generates new test cases from the configured grammar|
|GramatronRandomMutator|Mutator|Generates test cases by regenerating from the grammar starting at a random location|
|GramatronRecursiveMutator|Mutator|Generates test cases by expanding recursive features in a test case|
|GramatronSpliceMutator|Mutator|Generates test cases by splicing two together in a grammar aware way|
|DictionaryMutator|Mutator|Generates test cases by randomly inserting user defined strings|

### Executor and Feedback Modules

|Module Name|Type|Summary
| --------- | --- |------ |
|AFLExecutor|Executor|Executes SUT using AFL++ forkserver|
|AFLFeedback|Feedback|Evaluates AFL++ execution results|
|AFLFavoredFeedback|Feedback|More complex version of AFLFeedback that includes favored test cases|

### Output Modules

|Module Name|Type|Summary
| --------- | --- |------ |
|CorpusMinimization|Output|Removes test cases that don't provide unique coverage paths|
|ComputeStats|Output|Computes execution metrics and writes them to metadata|
|CSVMetadataOutput|Output|Writes all numeric metadata values into a CSV file|
|LoggerMetadataOutput|Output|Writes all numeric metadata values to the Logger|
|SaveCorpusOutput|Output|Saves a copy of all of the test cases in long term storage to disk|
|StatsOutputModule|Output|Prints basic performance metrics to the log file|

# AFLForkserverExecutor

## SUT Execution Parameters & Constraints
AFLForkserverExecutor implements calibration testing that can be invoked by a controller module. During calibration, test cases provided as part of the seed corpus are measured for their execution time and coverage. Calibration test case execution times are primarily useful to calculate performant timeout values to identify hanging SUTs during the fuzzing campaign. These test cases preferably run to completion without hangs or crashes. The configuration option, `maxCalibrationCases` controls the number of tests used towards calibration. 

A larger calibration amount may be useful for SUTs with highly variant execution times. Specify this option with:
```yaml
AFLForkserverExecutor:
  maxCalibrationCases: 500 # Defaults to 300
```

AFLForkserverExecutor supports specifying a manual timeout value.  This timeout is used to determine when an execution of the SUT has hung.  This is an optional parameter, and when not manual timeout is specified, the executor will instead automatically compute a timeout value based on the initial seeds. Specifying this value will override the timeout values calculated by calibration.

Care must be taken when manually specifying this value, as a timeout that is too short will result in test cases being erroneously identified as hanging, and a timeout value that is too long will result in degraded fuzzing performance.

Add the following configuration section to specify this value:
```yaml
AFLForkserverExecutor:
  timeoutInMs: 100 #This would specify a 100ms timeout value
```

AFLForkserverExecutor also supports configuring memory limits for SUTs. Using sane memory limits will prevent SUTs that have leaky memory from consuming large amounts of machine resources, potentially reducing fuzzing performance. However, overriding the safe default value of 128MB may be necessary for SUTs that use large amounts of memory, or utilize memory-intensive sanitizers such as ASAN (the useASAN configuration removes the memory limit).

To specify a SUT memory limit, use the following configuration:
```yaml
AFLForkserverExecutor:
  memoryLimitInMB: 256 # This would specify a 256MB memory limit
```

## Debug Logs
AFLForkserverExecutor can record SUT stdout and stderr data. These logs are useful when debugging a potential issue with the fuzzing campaign, such as a SUT that's missing command line arguments, or libraries. It may also indicate some errors in your config. 

To enable this debug logging, set the `debugLog` to `true` and optionally change the default locations for files using the `stdout` and `stderr` configurations in conjunction with `debugLog`. For example:
```yaml
AFLForkserverExecutor:
  debugLog: true # Enable SUT stdout/stderr debug logs
  stdout: mysut_stdout # OPTIONAL file name for stdout
  stderr: mysut_stderr # OPTIONAL file name for stderr
```

## Coverage Maps
SUT binaries may have non-default map sizes built in at compile-time. AFLForkserverExecutor attempts auto-detection of this map size by probing the SUT, however, in cases where this process fails, you may specify the map size via the `mapSize` configuration. For example:
```yaml
AFLForkserverExecutor:
  mapSize: 65536 # Specify a map-size of 65KB
```

Further, AFLForkserverExecutor offers a few options for deciding when to record coverage data during the fuzzing campaign. For each test case, the executor will decide based on the configuration whether to commit the coverage bitmap to storage. The configuration options `alwaysWriteTraceBits`, `traceBitsOnNewCoverage`, and `writeStats` control these capabilities.

When `traceBitsOnNewCoverage` is set to true, the executor will only write coverage data to storage if the associated test case discovers new coverage. This is the default behavior. 
```yaml
AFLForkserverExecutor:
  traceBitsOnNewCoverage: true # Defaults to true
```

When `alwaysWriteTraceBits` is set to true, the executor will always save the coverage bitmap to storage.
```yaml
AFLForkserverExecutor:
  alwaysWriteTraceBits: true 
```

Finally, `writeStats` will record cumulative coverage data to storage. This is useful for output modules that display incremental progress during the fuzzing campaign. 
```yaml
AFLForkserverExecutor:
  writeStats: true
```

## Sanitizers & Alternative SUT instrumentation
AFLForkserverExecutor supports SUTs that are instrumented with CmpLog, ASAN, LSAN, MSA and UBSAN. When enabled, AFLForkserverExecutor may include an additional coverage map (in the case of CmpLog), or unique error codes (in the case of the sanitizers). Alternatively, some SUTs, either by some instrumentation or through source-level implementation, may exit with specific error codes, which can be specified with the `customExitCode` configuration option, to indicate crashing behavior. 
CmpLog-instrumented SUTs are required for RedPawn, which is documented below. 
For sanitizer-instrumented SUTs, configure the AFLForkserverExecutor with _one_ of `useASAN`, `useLSAN`, `useMSAN`, `useUBSAN`; AFLForkserverExecutor does not currently support SUTs instrumented with multiple sanitizers.

Here's an example of enabling fuzzing of an ASAN-instrumented SUT: 
```yaml
AFLForkserverExecutor:
    useASAN: true
```
ASAN significantly increases SUT memory usage. To accomodate this, enabling `useASAN` will disable the SUT process's memory limit (unless explicitly specified with `memoryLimitInMB`.

# AFLFeedback and AFLFavoredFeedback 
AFLFeedback and AFLFavoredFeedback supports adjusting the relative weights of the components used to compute the fitness of each test case.  Because test cases are sorted in storage by their fitness, and the Input Generators provided by VMF use a weighted random selection that favors more fit test cases, changing the fitness computation changes which test cases are selected for mutation.

AFLFeedback and AFLFavoredFeedback compute fitness as a function of code coverage, execution speed, and test case size.  AFLFavoredFeeback adds an additional factor, "favored", that increases the fitness of the test cases that reach unique areas of the code.  By increasing the relative weights a particular value, you can alter the fitness computation to more heavily weight faster test cases (speedWeight), smaller test cases (sizeWeight), or favored test cases (favoredWeight).  

Note: SizeWeight and speedWeight are both relative weights for which any value above 0.0 will apply additional weight to size or speed, respectively; setting either of these weights to 0 will remove the component from the computation entirely and negative values are not allowed. FavoredWeight is a simple multiplier for the whole fitness value for favored test cases, so only values above 1.0 will increase the weight of favored test cases (values of 1.0 and below will disabled the favored computation entirely, though it is preferable to just use the AFLFeedback module instead if favored computations are not desired).

This an area we are still experimenting with in VMF, but we have found reasonable values for sizeWeight and speedWeight to be in the range of 0.0-10.0.  What works best on one SUT may not work well for another, as they vary in how much they are effected by test case size or speed (some SUTS are significantly slower with certain inputs, others are more consistent).  Note the setting these too high will result in a decrease in code coverage by the fuzzer, because the coverage weight remains constant.  Setting them all to 0 will result in a fuzzer that only computes fitness based on code coverage.

Note that the fitness algorithm that uses custom weights is different than the fitness algorithm that does not.  So simply by enabling useCustomWeights, you will see different fuzzing performance (even using the default provided weights).

```yaml
AFLFavoredFeedback:
  useCustomWeights: false    #****First change this to true to enable custom weights***
  favoredWeight: 5.0         #*** Now you may adjust any of the other weights.  favoredWeight should be >1.0 ***
  sizeWeight: 1.0            #   sizeWeight should be 0.0-10.0 (0.0 will remove this factor. Must be nonnegative.)
  speedWeight: 5.0           #   speedWeight should be 0.0-10.0 (0.0 will remove this factor. Must be nonnegative.)
```

# AFLMutators
VMF includes a collection of mutators that are based on the mutation strategies used in AFL++.  Each mutator fills in a new StorageEntry with a copy of the input buffer that has modified or mutated in some way.  The exact mutations are described below.

## Bit and Byte Flipping Mutators
The following mutators all take an input test data buffer and randomly flip bits or bytes within the data (0s are turned into 1s, and 1s are turned into 0s).  These mutators will never change the size of the input, because they only flip existing values.
|Mutator|What is Flipped?|
|-----|-----|
|AFLFlipBitMutator|1 bit|
|AFLFlipByteMutator|1 byte|
|AFLFlip2BitMutator|2 consecutive bits|
|AFLFlip2ByteMutator|2 consecutive bytes|
|AFLFlip4BitMutator|4 consecutive bits|
|AFLFlip4ByteMutator|4 consecutive bytes|

## RandomByte Mutators

The following mutators manipulate a random byte from th input test data buffer.  These mutators never change the size of the input, because they only modify a single byte from the input.

* The AFLRandomByteMutator selects a random byte in the input buffer and then combines that byte with a random 1 byte value using an XOR operation.
* The AFLRandomByteAddSubMutator selects a random byte in the input buffer, subtracts a random 1 byte value from that byte, and then adds a different random byte value.

## Delete, Clone, and Splice Mutators

Each of these mutators does change the size of the input buffer.

The AFLCloneMutator clones a randomly selected portion of the input data, such that a section of the original input buffer is repeated in a random location within the buffer.  The insertion location and the size of the section are both randomized.  However, 25% of the time the mutator does a larger insertion of repeated bytes (up to 32768 bytes).

The AFLDeleteMutator removed a randomly selection portion of the input data.  This mutator can only work on input that are at least 2 bytes in length.  If it is called on shorter inputs, it will simply duplicate the input without mutation.

The AFLSpliceMutator take the input test buffer, and splices in data from a second unrelated test case.  The size of the resulting test case buffer will match the size of the second unrelated test cases, but the buffer will start with bytes from the input test buffer and end with bytes from the second test case.

# Dictionary Mutator
The DictionaryMutator reads in a list of strings defined by either the user or generated by the DictionaryInitialization module that are deemed "pertinent" to the fuzzer.  During test case mutation time a random string is pulled from the list and inserted in a random location within the test case to produce a new test case.  This testcase will be larger than the base test case.  The user provided list of strings is expected to conform to the following format:

```text
token="<user provided string>"
```

For example

```text
token="/lib64/ld-linux-x86-64.so.2"
```

# ComputeStats
The Compute Stats module produces runtime fuzzing statistics based on the contents of storage.  These statistics are written to the storage metadata.

It has a configuration option 'statsRateInSeconds' which controls how often the statistics are computed.  The TOTAL_XXX_CASES are counted on every pass through the fuzzing loop, because this requires direct observation of the new test cases on each pass.  All other values are computed based on the 'statsRateInSeconds' value.

The computed statistics include:
|Metadata Field Name|Type|Description|
|---|---|---|
|TOTAL_TEST_CASES|U64|The total number of new test cases executed in the main fuzzing loop|
|TOTAL_CRASHED_CASES|UINT|Of those test cases, the number that crashed|
|TOTAL_HUNG_CASES|UINT|Of those test cases, the number that hung|
|UNIQUE_TEST_CASES|UINT|The total number of unique, interesting test cases in storage (these are the test cases that the Fitness module has decided to save into long term storage)|
|UNIQUE_CRASHED_CASES|UINT|Of those unique test cases, the total number that crashed|
|UNIQUE_HUNG_CASES|UINT|Of those unique test cases, the total number that hung|
|LATEST_EXEC_PER_SEC|FLOAT|The current number of executions per second|
|AVERAGE_EXEC_PER_SEC|FLOAT|The average executions per second for the whole fuzzing run|
|SECONDS_SINCE_LAST_UNIQUE_FINDING|FLOAT|The number of seconds since VMF last found a unique, interesting test case|

# CorpusMinimization
The Corpus Minimization module periodically scans the testcase corpus and removes testcases that are not contributing to coverage. For each hit-count bit in the coverage bitmap, the testcase with the highest fitness is selected and the rest are culled.

This module performs the same functionality as the [AFL-cmin tool](https://manpages.ubuntu.com/manpages/bionic/man1/afl-cmin.1.html) but it runs automatically within the fuzzer and not as an external tool.

It has a configuration option `frequencyInMinutes` which determines how often the module is scheduled. The default value is 30 minutes. It reruns all the testcases during each culling, so the frequency should not be set too low. 

If no new testcases are discovered since the last culling, then the minimization is skipped.

```yaml
CorpusMinimization:
  frequencyInMinutes: 30 
```
A second configuration option `minimizeOnShutdown` controls whether or not minimization should occur when the fuzzer is shutdown.  The default value for this parameter is true.

**Note: Don't set both `minimizeOnShutdown` to false and `frequencyInMinutes` to 0 or this module will not run (unless it is a submodule of another module that calls it directly)**

CorpusMinimization requires a specific set of parameters when used as a submodule to enable server based corpus minimization (see [ServerCorpusMinOutput](#servercorpusminoutput)).

# CSVMetadataOutput
The CSV Metadata Output module will periodically log all numeric values in metadata to a CSV file (i.e. integer, unsigned integer, and floating point values).  A timestamp value will be included as the first column in the CSV (this timestamp is the number of seconds since the unix epoch on January 1st, 1970).  The first row of the file will contain the name of each of the fields.

The output file name defaults to metadata.csv, but may be changed using the `outputFileName` parameter.  The output file will be located in the VMF output directory.  The default output rate of 5 seconds may be changed using the `outputRateInSeconds` parameter.

```yaml
CSVMetadataOutput:
  outputFileName: "Test_3.CSV"
  outputRateInSeconds: 1
```

Users of this module will likely want to also use the ComputeStats module in order to produce more metadata values in storage, though this is not required, as any numeric values in metadata will be logged.  See [test/config/basicModules_extraLogging.yaml](../../test/config/basicModules_extraLogging.yaml) for an example of using this module with the ComputeStats module.


# Gramatron

Gramatron was the original research of Privast Shrivastava and Mathias Payer. Their work can be seen at the following references.
* [`Gramatron Reseach Paper`](https://dl.acm.org/doi/pdf/10.1145/3460319.3464814)
* [`Original Gramatron Source Repository`](https://github.com/HexHive/Gramatron)

These modules have taken their work and fitted it to be a set of VMF modules.

Currently, the user-defined grammar checking python scripts implemented in their code base are not implemented as VMF modules. If developers are looking to define their own grammars, it is recommended to look there for the testing scripts to test periodically as the grammars are being defined.

## Grammars

There are three grammars which are released with these modules.  They can be found in the source code under [data/grammars](../../data/grammars)

* mruby
* php
* js 

## Gramatron Modules

The following modules are provided:
* [`GrammarBasedSeedGen`](#GrammarBasedSeedGen)
* [`GramatronGenerateMutator`](#GramatronGenerateMutator)
* [`GramatronRandomMutator`](#GramatronRandomMutator)
* [`GramatronSpliceMutator`](#GramatronSpliceMutator)
* [`GramatronRecursiveMutator`](#GramatronRecursiveMutator)

### <a id="GrammarBasedSeedGen"></a>Initialization: `GrammarBasedSeedGen`

This initialization module is required to use the Gramatron mutators.

### <a id="GramatronGenerateMutator"></a>Mutator: `GramatronGenerateMutator`

This mutator uses the pushdown automata singleton class which is instatiated from the grammar defined in [`GrammarBasedSeedGen`](#GrammarBasedSeedGen) to generate new test cases and add them into storage. This mutator should always be enabled to keep the fuzzer from getting stuck by not exploring some parts of the grammar.

### <a id="GramatronRandomMutator"></a>Mutator: `GramatronRandomMutator`

This mutator pulls interesting test cases from storage and picks a random place in the automata walk representation of the test case to regenerate the end of the walk from.

### <a id="GramatronSpliceMutator"></a>Mutator: `GramatronSpliceMutator`

This mutator picks two random interesting test cases and attempts to find appropriate splice points in each test case to append the front of one test case to the tail of the other to make a new interesting test case to put into storage.

### <a id="GramatronRecursiveMutator"></a>Mutator: `GramatronRecursiveMutator`

This mutator picks a random test case and attempts to find recursive features of the test case to expand out. If no recursive features are found, it will do a random walk mutation instead.

## Gramatron Usage
To use the Gramatron modules, configure VMF to use the GrammerBasedSeedGen modules and one or more of the GramatronMutators.

There is no custom input generator module for Gramatron, just custom grammar-aware mutator modules which may be used by whichever input generator module is configured.

The following fragment shows a common use case:

```yaml
  controller: 
    className: IterativeController
    children:
      - className: GramatronBasedSeedGen
      - className: MOPTInputGenerator
      ...
  MOPTInputGenerator:
    children:
      - className: GramatronRandomMutator
      - className: GramatronSpliceMutator
      - className: GramatronRecursiveMutator
      - className: GramatronGenerateMutator
```

## TrivialSeedInitialization

This initialization module will initialize the storage module with a single string that is hard-coded in order to provide a trivial input into the SUT.

To enable the module, `TrivialSeedInitialization` must be listed in the `vmfModules` section of the config file.  This example used the configuration file [basicModules_trivial.yaml](../../test/config/basicModules_trivial.yaml) which adds the `TrivialSeedInitialization` to the basic VMF configuration discussed early.

## KleeInitialization

The Klee initialization module generates an initial corpus/seeds using symbolic execution. It relies on the third party tool, [KLEE](https://klee.github.io/), which must be `klee` must be installed and in your `$PATH` prior to using this module.  For installation directions, see [docs/external_projects.md/#klee](../external_projects.md#klee).

To enable the module, `KleeInitialization` must be listed in the `vmfModules` section of the config file.  This example used the configuration file [basicModules_klee.yaml](../../test/config/basicModules_klee.yaml) which adds the `KleeInitialization` to the basic VMF configuration discussed early.

Additionally, klee needs access to a bitcode input file that has been produces for your SUT (using clang -c -emit-llvm). The configuration file must specify the path to this bitcode `*.bc` file.  Both haystack_stdin.yaml an haystack.yaml specify that haystack.bc is located at test/haystackSUT/haystack.bc.

```yaml
vmfVariables:
  - &SUT_ARGV ["test/haystackSUT/haystack"]
  - &INPUT_DIR test/haystackSUT/test-input/
  - &LLVM_FILE test/haystackSUT/haystack.bc     #This is the path to haystack.bc#
```

To run this example configuration with the haystack SUT:
```bash
cd vmf_install/test/haystackSUT
clang -c -emit-llvm haystack.c -o haystack.bc
cd ../..
./bin/vader -c test/config/basicModules_klee.yaml -c test/haystackSUT/haystack_stdin.yaml
----or----
./bin/vader -c test/config/basicModules_klee.yaml -c test/haystackSUT/haystack_file.yaml
```

The initial test cases will be produced by the Klee Initialization module (instead of reading them in from a directory).

# LoggerMetadataOutput
The LoggerMetadataOutput module periodically logs all numeric values in metadata to the VMF Logger (i.e. integer, unsigned integer, and floating point values).  All item are logged at log level INFO.

The configuration parameter `outputRateInSeconds` is used to adjust the rate at which this logging occurs.  The default value is 5 seconds.

Users of this module will likely want to also use the ComputeStats module in order to produce more metadata values in storage, though this is not required, as any numeric values in metadata will be logged.  See [test/config/basicModules_extraLogging.yaml](../../test/config/basicModules_extraLogging.yaml) for an example of using this module with the ComputeStats module.

# MOPT
The MOPTInputGenerator uses the [MOPT optimization algorithm](https://www.usenix.org/system/files/sec19-lyu.pdf) to determine which mutator to select to mutate each testcase. This module contains a reimplementation of the algorithm based on the paper and provided reference implementation.  At a high level, the algorithm tracks how many times each mutator has been used and how often it has found interesting new testcases. It then uses these statistics to select mutators that are performing well using a Particle Swarm Optimization (PSO) algorithm.

MOPT has no required configuration options. However, a power user may configure several settings that influence the behavior of the algorithm as shown below. See the paper for more complete details. The `numSwarms` parameter controls how many swarms to instantiate in the Particle Swarm Optimization algorithm (default 5). More swarms will take longer to converge but may avoid local minima.

The `pilotPeriodLength` determines how many testcases are run by each swarm during the pilot phase (default 50,000). The pilot phase is used to collect statistics about how each swarm and mutator are performing. The `corePeriodLength` determines how many testcases are run by the best swarm during the core period (default 500,000). MOPT cycles repeatedly between a pilot period, a core period, and then an algorithmic weight update. Shorter pilot phases may allow faster weight converging, but at the cost of less data per update. Longer core periods allow MOPT to exploit best weights for longer, but prevent it from exploring other weights from other swarms.

Lastly, `pMin` determines the minimum selection probability for each mutator. For example, a `pMin` of 0.05 means that no mutator should be selected less than 5% of the time. Note that it may be appropriate to adjust this number based on the number of mutators that are being controlled by MOPT. The default value of 0 is a special value that signals MOPT to choose this value dynamically based on the number of mutators that are in use. 

```yaml
MOPTInputGenerator:
  numSwarms: 5               # Number of swarms
  pilotPeriodLength: 50000   # Number of testcases executed during pilot phase
  corePeriodLength:  500000  # Number of testcases executed during core period
  pMin: 0                    # Minimum mutator probability (0 means ignore and use adaptive value)
  ```
# RedPawn
RedPawn is an input-to-state (I2S) analysis tool comparable to [RedQueen](https://www.ndss-symposium.org/wp-content/uploads/2019/02/ndss2019_04A-2_Aschermann_paper.pdf). Input-to-State analysis provides a lightweight alternative to full-blown taint tracking for overcoming common fuzzing bottlenecks such as "magic bytes", where there is a single correct value that random bitflip mutations are exceedingly unlikely to guess. RedPawn is able to extract or solve for the required value by inspecting comparison log data from the SUT, thus overcoming these limitations and achieving higher coverage. RedPawn is implemented as an InputGenerator module, the RedPawnInputGenerator.

**Note: RedPawn is compatible with AFL++ v4.30c instrumentation. It is not compatible with prior instrumentation versions.**

### Requirements and usage
RedPawn uses [AFL++'s CmpLog instrumentation](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.cmplog.md), which when added to the SUT causes a log of compare operations that take place to be sent to RedPawn for analysis. The use of RedPawn requires compiling two versions of the SUT: one built with normal AFL instrumentation, and a second with the CmpLog instrumentation (requires setting `AFL_LLVM_CMPLOG` at compile time, see CmpLog documentation).

See the MagicBytesSUT for a complete working example with configuration.

With RedPawn, a crash is quickly found: `./bin/vader -c ./test/config/defaultModules_RedPawn.yaml -c ./test/magicBytesSUT/magicbytes.yaml`

Without RedPawn, no crash is found: `./bin/vader -c ./test/config/defaultModules.yaml -c ./test/magicBytesSUT/magicbytes.yaml`

As with all of our example configurations, the [test/config/defaultModules_RedPawn.yaml](../../test/config/defaultModules_RedPawn.yaml) configuration file can be used with your own SUT.

Note that RedPawn requires two additional executors:

- An additional executor to be configured to execute the CmpLog version of the SUT. RedPawn finds this executor module by name, which must be called `cmplogExecutor`.

- An additional standard (AFL instrumented, non-CmpLog) executor that it can use for colorization, an internal step during which additional entropy is added to analyzed testcases. RedPawn finds this executor module by name, which must be called `colorizationExecutor`.

The RedPawnInputGenerator runs once on each new testcase that is discovered while fuzzing. As such, it also requires a controller that can detect when new coverage is found and switch to the RedPawnInputGenerator. The `NewCoverageController` can be used for this purpose, and is the controller that is selected in our default configuration.

The following yaml configuration sections show an example usage of RedPawnInputGenerator:

```yaml
vmfModules:
  storage:
    className: SimpleStorage
  controller:
    className: NewCoverageController
    children:
      - className: MOPTInputGenerator
      - className: RedPawnInputGenerator
      ...
  RedPawnInputGenerator:
    children:
      - id: colorizationExecutor
        className: AFLForkserverExecutor
      - id: cmplogExecutor
        className: AFLForkserverExecutor

NewCoverageController:
  primaryInputGenerator: MOPTInputGenerator
  newCoverageInputGenerator: RedPawnInputGenerator

# Main executor
AFLForkserverExecutor:
  sutArgv: ["path/to/sut/sut", "@@"]
  
# Executor that includes CmpLog instrumentation
cmplogExecutor:
  sutArgv: ["path/to/sut/sut_cmplog", "@@"]
  cmpLogEnabled: true # This flag enables CmpLog
  memoryLimitInMB: 400 # Additional memory for CmpLog
  writeStats: false # Only main executor reports stats

# Executor that has only AFL coverage instrumentation
# The alwaysWriteTraceBits flag must be set for this executor.
colorizationExecutor:
  sutArgv: ["path/to/sut/sut", "@@"]
  alwaysWriteTraceBits: true #must be set
  writeStats: false # Only main executor reports stats
```

### Notes
The reported exec/s speed by the stats module does not account for time spent in RedPawn, and so the fuzzer will appear to slow down when RedPawn is enabled.

RedPawn runs once for each new testcase and will typically dominate the fuzzer's activity early on in fuzzing while new coverage is still being rapidly found. This is expected behavior.

In the RedPawn logs:

"testcases in queue" refers to how many new unique coverage testcases RedPawn has yet to be process.

"testcases generated from last seed testcases" displays how many new testcases were created by RedPawn using just the last single testcase.

"testcases generated total" displays how many testcases RedPawn has generated total for the entire executution.


# StatsOutput
The StatsOutput module writes periodic performance metrics for the VMF fuzzer.  By default, this module writes the performance metrics to the console and log file every 5 seconds.  You will likely want to turn down this data rate for an actual fuzzing campaign.

Note: This modules uses the performance metrics that are produced by the ComputeStats module, so you will
not be able to use this module without also including the ComputeStats module.

```yaml
StatsOutput:
  outputRateInSeconds: 600 #this would set the output rate to once every 10 minutes
```

To support distributed fuzzing mode, StatsOutput can also be configured to send performance metrics to the server instead.  Set the paramter `sendToServer` to true in order when using distributed fuzzing. When `sendToServer` is true, the default output rate is 20 seconds (vs. 5 seconds when writing to the console and log file).  We do not recommend setting this rate below 20 seconds when running distributed fuzzing unless you are running a very small number of VMFs.

```yaml
StatsOutput:
  sendToServer: true #use this setting for distributed fuzzing
  outputRateInSeconds: 60 #this would set the output rate to once a minute
```

# SaveCorpusOutput
The SaveCorpusOutput module saves all interesting test cases to disk. By default, this module saves a copy of each test case that caused the SUT to crash or hang. This module may be configured to save test cases tagged with other criteria as well. Further, this module can be configured to save metadata information for each test case, such as mutator information.

```yaml
SaveCorpusOutput:
  tagsToSave: ["CRASHED", "HUNG", "MYTAG"] #test cases with any of these labels will be saved
  recordTestMetadata: true #use this to record metadata
```

# Controller Modules

All of these controllers support the `keepAllSeeds` parameter. If set to true, all initial testcases will be saved and added to the fuzzing queue. If set to false, only seeds with new coverage will be kept.

All of these controllers also support a number of distributed fuzzing related configuration options -- see [Controller Settings for Distributed Fuzzing](#controller-settings)

## AnalysisController
This controller is designed for analysis-oriented tasks, where a number of test cases need to be executed once followed by the execution of one or more output modules to analyse the results.  This controller is used to support server based corpus minimization for distributed fuzzing.  At least one executor and feedback module are required.  Typically users of this module will want to use at least one output module as well, but it is not required to do so.

The execution pattern is to run the initialization modules and the input generation modules once, then the executor and feedback modules, and finally the output modules. When running in standalone mode, this will occur in a single pass through the fuzzing loop. When using this controller for distributed fuzzing, it may take more than one pass through the fuzzing loop to run everything once (because server test cases are loaded in batches).  In this case, the output modules will only be run once in the final pass through the fuzzing loop (after all of the test cases have executed).

## IterativeController
The IterativeController simply iterates through each module, calling them in sequence.  This controller supports one InputGenerator, one Executor and Feedback module, and any number of Initialization and Output modules.  The Executor, Feedback, and InputGeneration modules are required.

In addition to the distributed fuzzing configuration options, this controller supports a `runTimeInMinutes` parameter which controls whether or not the controller will shut down automatically after fuzzing for a specific period of time.  The default value for this parameter, which means the controller will not shutdown until the user terminates the fuzzer.  Note that this the minimum time that the fuzzer must run before terminating, and the actual run time may be slightly longer, particularly for slow running SUTs, as the controller only terminates after the completion of the current fuzzing loop.

```yaml
IterativeController:
  runTimeInMinutes: 60 #This would configure the fuzzer to run for an hour
```

## NewCoverageController
The NewCoverageController is similar to the IterativeController, except that it supports two InputGenerator modules.  This controller will temporarily toggle to an alternative input generator every time there is are new, interesting test cases saved in storage (typically this occurs due to new coverage, though the exact decision is made in the feedback module).  The examineTestCaseResults() method is called on both input generators during each pass through the fuzzing loop, but the addNewTestCases() method is called on only the active input generator.

For example, the configuration below is used to have the RedPawnInputGenerator execute each time there is a test case with new code coverage.  The RedPawnInputGenerator will run each time there is a new saved test case identified by the feedback module.  This allows RedPawn the opportunity to generate new test cases that are based on this new, interesting test case.
```yaml
controller:
  primaryInputGenerator: MOPTInputGenerator
  newCoverageInputGenerator: RedPawnInputGenerator
```

Note: In order to temporarily toggle to an alternatte InputGenerator, the newCoverageInputGenerator must have a concept of completion (specifically, an examineTestCaseResults() method that will return true, indicating that the input generation strategy is complete).  MOPTInputGenerator and GeneticAlgorithmInputGenerator are not appropriate to use as new coverage input generators because their examineTestCaseResults() methods always return false, indicating that that are not done.

The NewCoverageController supports the `runTimeInMinutes` parameter with the same behavior as the IterativeController.

## RunOnceController 
The RunOnceController runs each of its submodules exactly once and then completes.  This module could be used to implement any kind of behaviors that should occur only once.  This Controller supports any number of initializationModules, inputGeneratorModules, and outputModules.  Up to one executor and feedback modules are supported.  All module types are optional, however a feedback module cannot be specified without an executor to go with it, and if an executor module is used a feedback modules must be provided as well.

This module will not do anything unless at lease one submodule is specified in the configuration file.  It does not provide any additional configuration options (beyond the default options supported by all core module controllers).

# Distributed Fuzzing Modules and Configuration Options
These modules and settings are only used when running VMF in distributed fuzzing mode.

## ServerSeedInitialization and ServerCorpusInitialization
ServerSeedInitialization retrieves seed information from the server.  By default it will retrieve either the initial seeds corpus configured in the scenario or, if the most recent minimized corpus (if there is one) filtered to return only test cases that are tagged as "RAN_SUCCESSFULLY".  This initialization module is used in our example basic and default module configuration files.

ServerCorpusInitialization is similar, but instead retrieves the entire common corpus, regardless of tags or whether minimization has occured.  This initialization module is used in our example corpus minimization configuration file.

### ServerSeedInitialization Parameters
The `getMinCorpus` parameter controls whether or not a minimized corpus should be retrieved if one is available.  If set to false, the module will always retrieve the intial seed corpus (from the scenario configuration).

```yaml
ServerSeedInitialization:
  getMinCorpus: false #initial seeds will always be used
```

The `corpusTags` parameter controls which test cases should be retrieved by filtering by tag.  This is only relevant when retrieving the minimized corpus -- the seed corpus doesn't have any tags.

The default value of "[RAN_SUCCESSFULLY]" retrieves only the test cases that were tagged accordingly (e.g. only the non-crashing, non-hanging test cases).  You may replace this with a different list of tags to retrieve a different subset of the common corpus.

The example below would retrieve only the test cases tagged as "CRASHED" or "HUNG":
```yaml
ServerSeedInitialization:
  corpusTags: ["CRASHED","HUNG"]
```

### ServerCorpusInitialization Parameters
The `corpusTags` parameter controls which test cases should be retrieved by filtering by tag.  The default value "" retrieves all test cases regardless of tag.  You may replace this with a list of tags to retrieve a different subset of the common corpus.

The example below would retrieve only the test cases tagged as "CRASHED" or "HUNG":
```yaml
ServerCorpusInitialization:
  corpusTags: ["CRASHED","HUNG"]
```

The `writeServerURL` parameter is used to control whether or not the server provided URL for the test case is also written to storage.  This is needed to support server based corpus minimization, as the module needs to know what the URLs were in order to tell the server which files to keep.  Set to `false` to disable this behavior
```yaml
ServerCorpusInitialization:
  writeServerURL: false #this would disable writing the URL
```

## ServerCorpusOutput
The ServerCorpusOutput modules sends new interesting test cases to the server.  ***This module has to be present for a VMF Fuzzer to contribute test cases to the common corpus***.  This module has no configuration options.

The `serverDelayTimeinSecs` parameter is used to control the minimum time that a VMF will wait between sending new test cases to the server.  The default value is 30s.

The `serverDelayOverrideCount` parameter can be used to force a VMF to send data sooner than the `serverDelayTimeinSecs` parameter when a large number of test cases have accumulated (i.e. if the value is set to 500, then VMF will send data as soon as it has 500 test cases even if hasn't been 30s since it last sent data).  This setting is disabled by default, but is useful if the size of the test case zip file is a problem for the server (particular in the initial phases of fuzzing, when there are a lot of findings).

## ServerCorpusMinOutput 
The ServerCorpusMinOutput module is used to perform server based corpus minimization.  This module is intended to be used with the RunOnceController.  It is not currently implemented to support periodic minimization.   This module requires a submodule that performs the actual minimization algorithm.  Currently VMF Core Modules includes only one appropriate submodule, [CorpusMinimization](#corpusminimization).  CorpusMinimization must be configured as follows to support ServerCorpusMinOutput.  This allows ServerCorpusMinimization to control when CorpusMinimization runs.

```yaml
CorpusMinimization:
  minimizeOnShutdown: false
```

Note: this module  relies on the "FILE_URL" key being written by another module in the system (e.g. ServerCorpusInitialization with `writeServerURL` set to true).

## Parameters for Distributed Fuzzing

### StatsOutput Settings
The StatsOutput module must have its `sendToServer` parameter set to true for distributed fuzzing mode in order for performance metrics to be transmitted to the server. 
See [StatsOutput](#statsoutput) for more information on this setting.

### Controller Settings
There are three configuration options built into the base ControllerModulePattern class that support distributed fuzzing. All configure how and when the controller retrieves corpus updates from the server (this means pulling in test cases that were generated by other VMF fuzzers in the cluster).
 
 `corpusInitialUpdateMins` sets the minimum number of minutes that must pass before the controller will perform the first corpus update. `corpusUpdateRateMins` sets a minimum rate for the controller to retrieve subsequent corpus updates from the server.  The default value for both is 5min, which provides for effectively constant corpus exchange (the minimum values are 1min, we recommend not going below 5min unless you are using a very small number of VMFs).

 The `batchSize` parameter controls how many test cases are pulled in from the server on each fuzzing loop.  All the test cases will eventually be pulled in, but this parameter limits how many get pulled in at once (in order to limit the RAM usage by VMF).

The `corpusUpdateTags` parameter controls which test case tags are retrieved by the controller.  The default value is ["RAN_SUCCESSFULLY"], which will retrieve only the test cases ran succesfully (i.e. didn't hang or crash).  This is the correct value if you are using VMF Core Modules for configuring your fuzzer.

To set these parameters, set a value in the config section for the controller.  For example, if you are using IterativeController, and want the fuzzer to run for 3 hours before performing the first corpus update, and then do an update hourly after that, use the following settings:
```yaml
IterativeController:
  corpusInitialUpdateMins: 180 #The first corpus update should be 3 hours into fuzzing
  corpusUpdateRateMins: 60 #Subsequence updates are once an hour
```








