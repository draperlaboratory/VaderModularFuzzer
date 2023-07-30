# Core Modules
This document provides more detailed documentation for the VMF Core Modules.

* [Core Module Overview](#core-module-overview)
    + [Storage Usage](#storage-usage)
    + [Metadata Usage](#metadata-usage)
* [AFLForkserverExecutor](#aflforkserverexecutor)
* [AFLFavoredFeedback](#aflfavoredfeedback)
* [KleeInitialiation](#kleeinitialization)
* [CorpusMinimization](#corpusminimization)
* [MOPT](#mopt)
* [StatsOutput](#statsoutput)
* [Distributed Fuzzing Modules and Configuration Options](#distributed-fuzzing-modules-and-configuration-options)
    + [ServerSeedInitialization and ServerCorpusInitialization](#serverseedinitialization-and-servercorpusinitialization)
    + [ServerCorpusOutput](#servercorpusoutput)
    + [ServerCorpusMinOutput](#servercorpusminoutput)
    + [RunOnceController](#runoncecontroller)
    + [Parameters for Distributed Fuzzing](#parameters-for-distributed-fuzzing)



## Core Module Overview
The following core modules are provided along with VMF.  A brief summary of each module's function is provided below.

|Module Name|Type|Summary
| --------- | --- |------ |
|SimpleStorage|Storage|The default implementation of Storage|
|IterativeController|Controller|Controls a configurable set of modules to run a fuzzer|
|DirectoryBasedSeedGen|Initialization|Creates initial test cases based on contents of a directory|
|StringsInitialization|Initialization|Uses the strings utility to create initial test cases|
|KleeInitialization|Initialization|Uses Klee to create initial test cases|
|GeneticAlgorithmInputGenerator|InputGenerator|Manages mutators by selecting a base test and which mutators to mutate it with|
|MOPTInputGenerator|InputGenerator|Uses an optimized mutation algorithm to select mutators based on their prior performance**|
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
|RadamsaMutator|Mutator|Performs Randamsa style mutation of test case|
|CRC32Formatter|Formatter|Adds a CRC32 checksum to a test case|
|AFLExecutor|Executor|Executes SUT using AFL++ forkserver|
|AFLFeedback|Feedback|Evaluates AFL++ execution results|
|AFLFavoredFeedback|Feedback|More complex version of AFLFeedback that includes favored test cases|
|CorpusMinimization|Output|Removes test cases that don't provide unique coverage paths|
|SaveCorpusOutput|Output|Saves a copy of all of the test cases in long term storage to disk|
|StatsOutputModule|Output|Prints basic performance metrics to the log file|

### Storage Usage
These are the core modules that read and write data in storage.  Note that ExecutorModules and StorageModules do not use storage (the StorageModule is storage, so it stores all of the fields and tags, but does not rely on any specific content being there).

|Module Name|TEST_CASE (buffer)|TEST_CASE_FORMATTED (buffer)|FITNESS (float)|MUTATOR_ID (int)|CRASHED (tag)|HUNG (tag)|RAN_SUCCESSFULLY (tag)| FAVORED (tag) |
|-----|-----|-----|-----|-----|----|----|----|----|
|AFLFeedback|||Writes||Writes|Writes|Writes
|AFLFavoredFeedback|||Writes||Writes|Writes|Writes|Reads/Writes|
|AFL***Mutator|Writes|
|CorpusMinimization|Reads|Reads|||||Reads
|DirectoryBasedSeedGen|Writes
|GeneticAlgorithmInputGenerator|||**||||Reads
|IterativeController|Reads|Writes|
|MOPTInputGenerator|||**|Reads/Writes|
|RadamsaMutator|Reads/Writes|
|SaveCorpusOutput|Reads|Reads|||Reads|Reads||
|StatsOutputModule|||||Reads|Reads||
|StringsInitialization|Writes|
|KleeInitialization|Writes|


** GeneticAlgorithmInputGenerator and MOPTInputGenerator do not read or write fitness, but they do rely on the fact that Storage returns values sorted by fitness.

### Metadata Usage
These are the core modules that read and write metadata in storage.
|Module Name|TOTAL_TEST_CASES (int)|TOTAL_CRASHED_CASES (int)|TOTAL_HUNG_CASES (int)|TOTAL_BYTES_COVERED (int)|MAP_SIZE (int)
| --------- | --- |------ |------| ----- | ---- |
|AFLFeedback||Writes|Writes|Writes|Writes|
|AFLFavoredFeedback||Writes|Writes|Writes|Writes|
|IterativeController|Writes|
|StatsOutputModule|Reads|Reads|Reads|Reads|Reads|

# AFLForkserverExecutor
AFLForkserverExecutor supports specifying a manual timeout value.  This timeout is used to determine when an execution of the SUT has hung.  This is an optional parameter, and when not manual timeout is specified, the executor will instead automatically compute a timeout value based on the initial seeds.

Care must be taken when manually specifying this value, as a timeout that is too short will result in test cases being erroneously identified as hanging.

Add the following configuration section to specify this value:
```yaml
AFLForkserverExecutor:
  timeoutInMs: 100 #This would specify a 100ms timeout value
```

# AFLFavoredFeedback 
AFLFavoredFeedback supports adjusting the relative weights of the components used to compute the fitness of each test case.  Because test cases are sorted in storage by their fitness, and the Input Generators provided by VMF use a weighted random selection that favors more fit test cases, changing the fitness computation changes which test cases are selected for mutation.

AFLFeedback and AFLFavoredFeedback compute fitness as a function of code coverage, execution speed, and test case size.  AFLFavoredFeeback adds an additional factor, "favored", that increases the fitness of the test cases that reach unique areas of the code.  By increasing the relative weights a particular value, you can alter the fitness computation to more heavily weight faster test cases (speedWeight), smaller test cases (sizeWeight), or favored test cases (favoredWeight).  

Note: SizeWeight and speedWeight are both relative weights for which any value above 0.0 will apply additional weight to size or speed, respectively; setting either of these weights to 0 will remove the component from the computation entirely.  FavoredWeight is a simple multiplier for the whole fitness value for favored test cases, so only values above 1.0 will increase the weight of favored test cases (values of 1.0 and below will disabled the favored computation entirely, though it is preferable to just use the AFLFeedback module instead if favored computations are not desired).

This an area we are still experimenting with in VMF, but we have found reasonable values for sizeWeight and speedWeight to be in the range of 0.0-10.0.  What works best on one SUT may not work well for another, as they vary in how much they are effected by test case size or speed (some SUTS are significantly slower with certain inputs, others are more consistent).  Note the setting these too high will result in a decrease in code coverage by the fuzzer, because the coverage weight remains constant.  Setting them all to 0 will result in a fuzzer that only computes fitness based on code coverage.

Note that the fitness algorithm that uses custom weights is different than the fitness algorithm that does not.  So simply by enabling useCustomWeights, you will see different fuzzing performance (even using the default provided weights).

```yaml
AFLFavoredFeedback:
  useCustomWeights: false    #****First change this to true to enable custom weights***
  favoredWeight: 5.0         #*** Now you may adjust any of the other weights.  favoredWeight should be >1.0 ***
  sizeWeight: 1.0            #   sizeWeight should be 0.0-10.0 (0.0 will remove this factor)
  speedWeight: 5.0           #   speedWeight should be 0.0-10.0 (0.0 will remove this factor)
```

# KleeInitialization

The Klee initialization module generates an initial corpus/seeds using symbolic execution. It relies on the third party tool, [KLEE](https://klee.github.io/), which must be `klee` must be installed and in your `$PATH` prior to using this module.  For installation directions, see [docs/external_projects.md/#klee](docs/external_projects.md/#klee).

To enable the module, `KleeInitialization` must be listed in the `vmfModules` section of the config file.  This example used the configuration file [basicModules_klee.yaml](/test/config/basicModules_klee.yaml) which adds the `KleeInitialization` to the basic VMF configuration discussed early.

Additionally, klee needs access to a bitcode input file that has been produces for your SUT (using clang -c -emit-llvm). The configuration file must specify the path to this bitcode `*.bc` file.  [haystack_klee.yaml](/test/haystackSUT/haystack_klee.yaml) provides an example configuration file that specifies that haystack.bc is located at test/haystackSUT/haystack.bc.

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
./bin/vader -c test/config/basicModules_klee.yaml -c test/haystackSUT/haystack_klee.yaml
```

Additional initial test cases will be produced by the Klee Initialization module.

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

# StatsOutput
The StatsOutput module writes periodic performance metrics for the VMF fuzzer.  By default, this module writes the performance metrics to the console and log file every 5 seconds.  You will likely want to turn down this data rate for an actual fuzzing campaign.

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

## ServerCorpusMinOutput 
The ServerCorpusMinOutput module is used to perform server based corpus minimization.  This module is intended to be used with the RunOnceController.  It is not currently implemented to support periodic minimization.   This module requires a submodule that performs the actual minimization algorithm.  Currently VMF Core Modules includes only one appropriate submodule, [CorpusMinimization](#corpusminimization).  CorpusMinimization must be configured as follows to support ServerCorpusMinOutput.  This allows ServerCorpusMinimization to control when CorpusMinimization runs.

```yaml
CorpusMinimization:
  minimizeOnShutdown: false
```

Note: this module  relies on the "FILE_URL" key being written by another module in the system (e.g. ServerCorpusInitialization with `writeServerURL` set to true).

## RunOnceController 
The RunOnceController runs each of its submodules exactly once and then completes.  This module is currently used to support server based corpus minimization, but it could be used to implement other kinds of behaviors that should occur only once.

This module will not do anything unless at lease one submodule is specified in the configuration file.  It does not provide any additional configuration options (beyond those supported by the base ControllerModule class).

## Parameters for Distributed Fuzzing

### StatsOutput Settings
The StatsOutput module must have its `sendToServer` parameter set to true for distributed fuzzing mode in order for performance metrics to be transmitted to the server. 
See [StatsOutput](#statsoutput) for more information on this setting.

### Controller Settings
There are two configuration options built into the base ControllerModule class that support distributed fuzzing.  `corpusUpdateRateMins` sets a minimum rate for the controller to retrieve new corpus updates from the server.  The default value is to retrieve every 5min (and the minimum value is 1min, we recommend not going below 5min unless you are using a small number of VMFs).

The `corpusUpdateTags` parameter controls which test case tags are retrieved by the controller.  The default value is ["RAN_SUCCESSFULLY"], which will retrieve only the test cases ran succesfully (i.e. didn't hang or crash).  This is the correct value if you are using VMF Core Modules for configuring your fuzzer.

To set either parameter, set a value in the config section for the controller you are using.  For example, if you are using IterativeController:
```yaml
  corpusUpdateRateMins: 60 #This would limit the rate to once an hour
```








