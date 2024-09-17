# VMF core modules configuration #

This document provides detailed information on the configuration options for VMF core modules. A general specification of the VMF configuration file format and the top-level sections is in [/docs/configuration.md](/docs/configuration.md).

Each module may have a configuration section for keys that are specific to that module.

Initialization modules
* [`DirectoryBasedSeedGen`](#section-directorybasedseedgen)
* [`GramatronBasedSeedGen`](#section-gramatronbasedseedgen)
* [`KleeInitialization`](#section-kleeinitialization)
* [`StringsInitialization`](#section-stringsinitialization)
* [`ServerSeedInitialization`](#section-serverseedinitialization)

Input Generator and Mutator modules
* [`GeneticAlgorithmInputGenerator`](#section-geneticalgorithminputgenerator)
* [`MOPTInputGenerator`](#section-moptinputgenerator)
* [`RedPawnInputGenerator`](#section-redpawninputgenerator)

Executor and Feedback modules
* [`AFLForkserverExecutor`](#section-aflforkserverexecutor)
* [`AFLFeedback`](#section-aflfeedback)
* [`AFLFavoredFeedback`](#section-aflfavoredfeedback)

Output modules
* [`ComputeStats`](#section-computestats)
* [`CorpusMinimization`](#section-corpusminimization)
* [`CSVMetadataOutput`](#section-csvmetadataoutput)
* [`LoggerMetadataOutput`](#section-loggermetadataoutput)
* [`SaveCorpusOutput`](#section-savecorpusoutput)
* [`StatsOutput`](#section-statsoutput)

Controller modules
* [`Parameters Common to All Controller Modules`](#section-parameters-common-to-all-controller-modules)
* [`AnalysisController`](#section-analysiscontroller)
* [`IterativeController`](#section-iterativecontroller)
* [`NewCoverageController`](#section-newcoveragecontroller)
* [`RunOnceController`](#section-runoncecontroller)

## <a id="DirectoryBasedSeedGen"></a>Section: `DirectoryBasedSeedGen`

Configuration information specific to the Directory-based Seed Generator module. 

### `DirectoryBasedSeedGen.inputDir`

Value type: `<path>`

Status: Required

Usage: Relative or absolute path to the directory containing seed test cases that VMF will load on startup. Each test case must be in a separate file; this module will create one new test case per file in the specified directory. The module does not recurse into subdirectories.

### Configuration example
```yaml
DirectoryBasedSeedGen:
  inputDir: /test/someapplication/seeds
```

## <a id="GramatronBasedSeedGen"></a>Section: `GramatronBasedSeedGen`

Configuration information specific to the Gramatron Grammer-based Seed Generator module.

### `GramatronBasedSeedGen.PDAPAth`

Value type: `<path>`

Status: Required

Usage: Relative or absolute path to the json-based pushdown automata definition for the grammar to be used during fuzzing.

### `GramatronBasedSeedGen.numTestCases`

Value type: `<int>`

Status: Required

Usage: Number of test cases to generate for the initial seed corpus before starting the fuzzing loop.

## <a id="KleeInitialization"></a>Section: `KleeInitialization`

Configuration information specific to the KleeInitialization module. 

### `KleeInitialization.bitcodeFilePath`

Value type: `<path>`

Status: Required

Usage: Relative or absolute path to the file containing LLVM bitcode that has been produced for the SUT (using `clang -c -emit-llvm`)

### Configuration example
```yaml
KleeInitialization:
  bitcodeFilePath: test/haystackSUT/haystack.bc
```

## <a id="StringsInitialization"></a>Section: `StringsInitialization`

Configuration information specific to the Strings Initialization module. This module runs the `strings` command on the given SUT, and creates a new test case from each line of output.

### `StringsInitialization.sutArgv`

Value type: `<list of strings>`

Status: Required

Usage: A list (array) of strings that represent the command line with arguments for the system under test (SUT). The first parameter must be the application itself, either with a relative path or an absolute path. Other command-line arguments are ignored by this module.

### Configuration example
```yaml
StringsInitialization:
  sutArgv: ["test/haystack", "@@"] 
```

## <a id="ServerSeedInitialization"></a>Section: `ServerSeedInitialization`

Configuration information specific to the ServerSeedInitialization module. This module is only used in conjunction with the CDMS server for distributed fuzzing.

### `ServerSeedInitialization.commonCorpusTags`

Value type: `<list of strings>`

Status: Optional

Default value: ["RAN_SUCCESSFULLY"]

Usage: A list (array) of strings that specifies the tags used to select which test cases are retrieved from the common corpus maintained by the CDMS server.

### `ServerSeedInitialization.writeServerURL`

Value type: `<bool>`

Status: Optional

Default value: false

Usage: This parameter specifies whether test cases retrieved from the CDMS server should include the CDMS server's URL as a field in local storage. This is used in conjuction with the `ServerCorpusOutput` module. If that module is used, the value of this parameter must be set to `true`.

### Configuration example
```yaml
ServerSeedInitialization:
  commonCorpusTags: ["RAN_SUCCESSFULLY", "CRASHED", "HUNG"]
  writeServerURL: 
```

## <a id="GeneticAlgorithmInputGenerator"></a>Section: `GeneticAlgorithmInputGenerator`

Configuration information specific to the GeneticAlgorithmInputGenerator module. 

### `GeneticAlgorithmInputGenerator.enableMutationOfCrashes`

Value type: `<bool>`

Status: Optional

Default value: false

Usage: This parameter controls whether the GA Input Generator module selects the next test case to mutate from all entries in the corpus, including test cases that are CRASHED or HUNG, or only from the set of test cases that ran normally.

### Configuration example
```yaml
GeneticAlgorithmInputGenerator:
  enableMutationOfCrashes: true
```

## <a id="MOPTInputGenerator"></a>Section: `MOPTInputGenerator`

Configuration information specific to the MOPTInputGenerator module. 

### `MOPTInputGenerator.numSwarms`

Value type: `<int>`

Status: Optional

Default value: 5

Usage: This parameter controls how many swarms to instantiate in the Particle Swarm Optimization algorithm. More swarms will take longer to converge but may avoid local minima.

### `MOPTInputGenerator.pilotPeriodLength`

Value type: `<int>`

Status: Optional

Default value: 50000

Usage: This parameter determines how many testcases are run by each swarm during the pilot phase. The pilot phase is used to collect statistics about how each swarm and mutator are performing.

### `MOPTInputGenerator.corePeriodLength`

Value type: `<int>`

Status: Optional

Default value: 500000

Usage: This parameter determines how many testcases are run by the best swarm during the core period. MOPT cycles repeatedly between a pilot period, a core period, and then an algorithmic weight update. Shorter pilot phases may allow faster weight converging, but at the cost of less data per update. Longer core periods allow MOPT to exploit best weights for longer, but prevent it from exploring other weights from other swarms.

### `MOPTInputGenerator.pMin`

Value type: `<float>`

Value range: 0.0 to 1.0

Status: Optional

Default value: 0.0

Usage: This parameter determines the minimum selection probability for each mutator. For example, a `pMin` of 0.05 means that no mutator should be selected less than 5% of the time. Note that it may be appropriate to adjust this number based on the number of mutators that are being controlled by MOPT. The default value of 0.0 is a special value that signals MOPT to choose this value dynamically based on the number of mutators that are in use.

### Configuration example
```yaml
MOPTInputGenerator:
  numSwarms: 5               # Number of swarms
  pilotPeriodLength: 50000   # Number of testcases executed during pilot phase
  corePeriodLength:  500000  # Number of testcases executed during core period
  pMin: 0.0                  # Minimum mutator probability (0.0 means ignore and use adaptive value)
```
## <a id="RedPawnInputGenerator"></a>Section: `RedPawnInputGenerator`

Configuration information specific to the RedPawn Input Generator module. 

### `RedPawnInputGenerator.colorizeMaxExecs`

Value type: `<int>`

Status: Optional

Default Value: 1,000

Usage: Specifies the maximum number of testcase executions that can take place during the colorization stage (which runs once per new interesting testcase). More executations can take longer, but produce testcases with more entropy which improves results and may save time during analysis. For slow or emulated SUTs, a smaller number may be preferable.

### `RedPawnInputGenerator.batchSize`

Value type: `<int>`

Status: Optional

Default Value: 1,000

Usage: Specifies the maximum number of testcases that can be created and added to storage in one run (invocation from controller) of the RedPawn Input Generator.  This setting is useful if you wish to reduce the overall memory usage associated with RedPawn, as producing fewer test cases at once will reduce the overall memory footprint.  Sometimes a single comparison instruction will produces a lot of possible test cases from RedPawn; this setting also serves as a limit for the total number of test cases that can be produces for each comparison instruction.

### `RedPawnInputGenerator.useDirectTransform`

Value type: `<bool>`

Status: Optional

Default Value: `true`

Usage: enables the Direct transform.

### `RedPawnInputGenerator.useReverseBytesTransform`

Value type: `<bool>`

Status: Optional

Default Value: `true`

Usage: enables the Reverse Bytes transform.

### `RedPawnInputGenerator.useOffsetTransform`

Value type: `<bool>`

Status: Optional

Default Value: `true`

Usage: enables the Offset transform.

### `RedPawnInputGenerator.useFactorTransform`

Value type: `<bool>`

Status: Optional

Default Value: `true`

Usage: enables the Factor transform.

### `RedPawnInputGenerator.useXORTransform`

Value type: `<bool>`

Status: Optional

Default Value: `true`

Usage: enables the XOR transform.


## <a id="AFLForkserverExecutor"></a>Section: `AFLForkserverExecutor`

Configuration information specific to the AFL Forkserver Executor module. 

### `AFLForkserverExecutor.sutArgv`

Value type: `<list of strings>`

Status: Required

Usage: A list (array) of strings that represent the command line with arguments for the system under test (SUT). The first parameter must be the application itself, either with a relative path or an absolute path. Other command-line arguments for the application are given in order as separate strings. The special argument `"@@"` is used when test case data should be passed from the fuzzer to the SUT in a file. The `"@@"` will be replaced at runtime with the filename.

### `AFLForkserverExecutor.timeoutInMs`

Value type: `<int>`

Status: Optional

Usage: Specifies the time in milliseconds that VMF will use to determine whether execution of the SUT has hung.  This is an optional parameter, and when not specified the executor will instead automatically compute a timeout value based on the initial seeds. Care must be taken when manually specifying this value, as a timeout that is too short will result in test cases being erroneously identified as hanging.

### `AFLForkserverExecutor.maxCalibrationCases`

Value type: `<int>`

Status: Optional

Default value: 300

Usage: Specifies a maximum number of tests use to calibrate AFLForkserverExecutor. These tests are primarily useful for calculating timeout values to detect hanging SUTs during the fuzzing campaign.

### `AFLForkserverExecutor.memoryLimitInMB`

Value type: `<int>`

Status: Optional

Default value: 128

Usage: Specifies a memory limit for the SUT. A value of 0 means unlimited.

### `AFLForkserverExecutor.debugLog`

Value type: `<boolean>`

Status: Optional

Default value: `false`

Usage: Records all SUT stdout/stderr to files. These file names default to `stdout` and `stderr` in the `forkserver/` directory under the output directory.

### `AFLForkserverExecutor.stdout`

Value type: `<string>`

Status: Optional

Default value: "stdout"

Usage: Specifies an alternate file name to capture SUT stdout logs. This config will only be used when the `debugLog` config option is set to `true`.

### `AFLForkserverExecutor.stderr`

Value type: `<string>`

Status: Optional

Default value: "stderr"

Usage: Specifies an alternate file name to capture SUT stderr logs. This config will only be used when the `debugLog` config option is set to `true`.

### `AFLForkserverExecutor.mapSize`

Value type: `<int>`

Status: Optional

Default value: 0

Usage: Specifies the SUT's coverage map size. A zero value here will invoke auto-detection of the map size.

### `AFLForkserverExecutor.alwaysWriteTraceBits`

Value type: `<boolean>`

Status: Optional

Default value: false

Usage: Configures the forkserver to record the full coverage map for each test case.

### `AFLForkserverExecutor.traceBitsOnNewCoverage`

Value type: `<boolean>`

Status: Optional

Default value: true

Usage: Configures the forkserver to record the full coverage map for test cases that discover new SUT coverage.

### `AFLForkserverExecutor.writeStats`

Value type: `<boolean>`

Status: Optional

Default value: true

Usage: Configures the forkserver to record cumulative coverage data for each test case.

### `AFLForkserverExecutor.customExitCode`

Value type: `<int>`

Status: Optional

Default value: Disabled

Usage: Treats a SUT that calls the `exit` system call with the specified value as a crashing case.

### `AFLForkserverExecutor.cmpLogEnabled`

Value type: `<boolean>`

Status: Optional

Default value: `false`

Usage: Enable SUTs instrumented with `cmpLog` to perform `cmpLog` coverage data collection.

### `AFLForkserverExecutor.useASAN`

Value type: `<boolean>`

Status: Optional

Default value: `false`

Usage: When enabled, this sets sane defaults for fuzzing ASAN-instrumented SUTs. Additionally, removes SUT memory limits (unless specified with `memoryLimitInMB`.

### `AFLForkserverExecutor.useLSAN`

Value type: `<boolean>`

Status: Optional

Default value: `false`

Usage: When enabled, this sets sane defaults for fuzzing LSAN-instrumented SUTs.

### `AFLForkserverExecutor.useMSAN`

Value type: `<boolean>`

Status: Optional

Default value: `false`

Usage: When enabled, this sets sane defaults for fuzzing MSAN-instrumented SUTs.

### `AFLForkserverExecutor.useUBSAN`

Value type: `<boolean>`

Status: Optional

Default value: `false`

Usage: When enabled, this sets sane defaults for fuzzing UBSAN-instrumented SUTs.

### Configuration example
```yaml
AFLForkserverExecutor:
  sutArgv: ["test/haystack", "@@"]  # Execute the haystack application in the test directory
                                    # "@@" indicates that the test case data is passed via a temporary file
  timeoutInMs: 100                  # Use 100ms timeout value
  memoryLimitInMB: 0                # Unlimited memory usage
```

## <a id="AFLFeedback"></a>Section: `AFLFeedback`

Configuration information specific to the AFLFeedback module. AFLFeedback and [AFLFavoredFeedback](#AFLFavoredFeedback) compute fitness as a function of code coverage, execution speed, and test case size. Both modules support adjusting the relative weights of the components used to compute the fitness of each test case. Because test cases are sorted in storage by their fitness, and the Input Generator modules provided with VMF use a weighted random selection that favors more fit test cases, changing the fitness computation changes which test cases are selected for mutation.

### `AFLFeedback.useCustomWeights`

Value type: `<boolean>`

Status: Optional

Default value: false

Usage: Enables the use of custom weighting factors in the AFL feedback algorithm.

### `AFLFeedback.sizeWeight`

Value type: `<float>`

Status: Optional

Default value: 1.0

Usage: Provides a relative weighting factor for the normalized size of the test case. Value should be in the range of 0.0 - 10.0. A value of 0.0 will remove this factor from the weighting algorithm.

### `AFLFeedback.speedWeight`

Value type: `<float>`

Status: Optional

Default value: 5.0

Usage: Provides a relative weighting factor for the normalized execution speed of the test case.Value should be in the range of 0.0 - 10.0. A value of 0.0 will remove this factor from the weighting algorithm.

### Configuration example
```yaml
AFLFeedback:
  useCustomWeights: true    # First change this to true to enable custom weights***
  sizeWeight: 1.0           # sizeWeight should be 0.0-10.0 (0.0 will remove this factor. Must be nonnegative.) 
  speedWeight: 5.0          # speedWeight should be 0.0-10.0 (0.0 will remove this factor. Must be nonnegative.) 
```
## <a id="AFLFavoredFeedback"></a>Section: `AFLFavoredFeedback`

Configuration information specific to the AFLFavoredFeedback module. This module extends [AFLFeedback](#AFLFeedback) and uses the same configuration parameters, plus the ones listed below.

AFLFeedback and AFLFavoredFeedback both compute fitness as a function of code coverage, execution speed, and test case size.  AFLFavoredFeeback adds an additional factor, "favored", that increases the fitness of the test cases that reach unique areas of the code

### `AFLFavoredFeedback.favoredWeight`

Value type: `<float>`

Status: Optional

Default value: 5.0

Usage: Provides a simple multiplier for the whole fitness value for favored test cases. Only values above 1.0 will increase the weight of favored test cases. Values below 1.0 will disable the favored computation entirely, though it is preferable to just use the AFLFeedback module instead if favored computations are not desired.

### Configuration example
```yaml
AFLFavoredFeedback:
  useCustomWeights: true    # Enable custom weights
  favoredWeight: 5.0        # favoredWeight should be >1.0
  sizeWeight: 1.0           # sizeWeight should be 0.0-10.0 (0.0 will remove this factor. Must be nonnegative.)
  speedWeight: 5.0          # speedWeight should be 0.0-10.0 (0.0 will remove this factor. Must be nonnegative.)
```
## <a id="ComputeStats"></a>Section: `ComputeStats`

Configuration information specific to the ComputeStats module, which computes statistics using the information in storage.

### `ComputeStats.statsRateInSeconds`

Value type: `<int>`

Status: Optional

Default value: 1

Usage: This parameter specifies how often the module should compute statistics, in seconds.  Note that a few of the total test case statistics have to be counted on every pass through the fuzzing loop, because they rely on directly observing new test cases on storage.  This parameter controls the rate of computing the remaining statistics.

### Configuration example
```yaml
ComputeStats:
  statsRateInSeconds: 10
```

## <a id="CorpusMinimization"></a>Section: `CorpusMinimization`

Configuration information specific to the CorpusMinimization module, which periodically scans the testcase corpus and removes testcases that are not contributing to coverage. 

### `CorpusMinimization.frequencyInMinutes`

Value type: `<int>`

Status: Optional

Default value: 30

Usage: This parameter specifies how often the module is scheduled, in minutes. It reruns all the testcases during each culling, so the frequency should not be set too low.

### Configuration example
```yaml
SaveCorpusOutput:
  frequencyInMinutes: 30
```
## <a id="CSVMetadataOutput"></a>Section: `CSVMetadataOutput`

Configuration information specific to the CSVMetadataOutput module, which periodically writes the numeric values in metadata to a CSV file.

### `CSVMetadataOutput.outputRateInSeconds`

Value type: `<int>`

Status: Optional

Default value: 5

Usage: This parameter specifies how often (in seconds) the metadata values should be written to the CSV file

### `CSVMetadataOutput.outputFileName`

Value type: `<string>`

Status: Optional

Default value: "metadata.csv"

Usage: This parameter specifies the filename of the CSV output file.  The directory used is the VMF output directory (vmfFramework.outputBaseDir).

### Configuration example
```yaml
CSVMetadataOutput:
  outputFileName: "Test_3.CSV"
  outputRateInSeconds: 1
```

## <a id="LoggerMetadataOutput"></a>Section: `LoggerMetadataOutput`

Configuration information specific to the LoggerMetadataOutput module, which periodically writes the numeric values in metadata to the VMF Logger.

### `LoggerMetadataOutput.outputRateInSeconds`

Value type: `<int>`

Status: Optional

Default value: 5

Usage: This parameter specifies how often (in seconds) the metadata values should be written to the Logger.

### Configuration example
```yaml
LoggerMetadataOutput:
  outputRateInSeconds: 60
```

## <a id="SaveCorpusOutput"></a>Section: `SaveCorpusOutput`

Configuration information specific to the SaveCorpusOutput module. This module writes test cases to disk that match the given tags.

### `SaveCorpusOutput.tagsToSave`

Value type: `<list of strings>`

Status: Optional

Default value: ["CRASHED", "HUNG"]

Usage: A list (array) of strings that will be used to select which test cases are written to disk. 

### Configuration example
```yaml
SaveCorpusOutput:
  tagsToSave: ["CRASHED", "HUNG", "MYTAG"]
```

## <a id="StatsOutput"></a>Section: `StatsOutput`

Configuration information specific to the StatsOutput module. 

### `StatsOutput.sendToServer`

Value type: `<bool>`

Status: Optional

Default value: false

Usage: This parameter controls whether the module outputs runtime statistics to the local console or to a distributed fuzzing CDMS server. If the value is `true` the data will be sent to the server address specified in [`vmfDistributed.serverURL`](/docs/configuration.md#vmfDistributed)

### `StatsOutput.outputRateInSeconds`

Value type: `<int>`

Status: Optional

Default value: 5 if `StatsOutput.sendToServer` is `false`, or 20 if `StatsOutput.sendToServer` is `true`

Usage: Specifies the frequency in seconds at which this module outputs runtime statistics.

### Configuration example
```yaml
StatsOutput:
  sendToServer: false
  outputRateInSeconds: 10
```

## <a id="ControllerCommonParameters"></a>Section: `Parameters Common to All Controller Modules`

Parameters that are common to all core Controller Modules (these parameters are supported by the base ControllerModulePattern class). Note that some are relevant ONLY for distributed fuzzing and will have no effect on standalone execution.

### `controller.keepAllSeeds`

Value type: `<bool>`

Status: Optional

Default value: true

Usage: If set to true, all seed testcases will be saved and inserted into the fuzzing queue regardless of their coverage or quality. If set to false, only testcases that the feedback module decides to keep (eg have new coverage) will be kept. When set to true, more care should be given to seed redundancy and quality.

### `controller.corpusInitialUpdateMins`

Value type: `<int>`

Status: Optional - Distributed fuzzing only

Default value: 5

Usage: This sets the minimum number of minutes that must pass before the controller will perform the first corpus update.  Do not configure this parameter to be smaller than 5min unless you are using a very small number of VMFs.

### `controller.batchSize`

Value type: `<int>`

Status: Optional - Distributed fuzzing only

Default value: 1000

Usage: This sets a maximum number of new test cases that will be pulled in from the server at once.  All the test cases will eventually be pulled in, but this parameter limits how many get pulled in at once (in order to limit the RAM usage by VMF).  When this value is too large, VMF will use an excessive amount of RAM (with resulting slow downs, consequently this value may need to be set to be smaller if the test cases are large).

### `controller.corpusUpdateRateMins`

Value type: `<int>`

Status: Optional - Distributed fuzzing only

Default value: 5

Usage: This sets a minimum rate for the controller to retrieve subsequent corpus updates from the server.  Do not configure this parameter to be smaller than 5min unless you are using a very small number of VMFs.

### `controller.corpusUpdateTags`

Value type: `<list of strings>`

Status: Optional - Distributed fuzzing only

Default value: ["RAN_SUCCESSFULLY"]

Usage: This parameter controls which test case tags are retrieved by the controller. The default value is ["RAN_SUCCESSFULLY"], which will retrieve only the test cases ran succesfully (i.e. didn't hang or crash). This is the correct value if you are using VMF Core Modules in your fuzzer.

## <a id="AnalysisController"></a>Section: `AnalysisController`
The AnalysisController does not support any custom configuration parameters.

## <a id="IterativeController"></a>Section: `IterativeController`
Configuration information specific to the IterativeController.
### `IterativeController.runTimeInMinutes`

Value type: `<int>`

Status: Optional

Default value: 0

Usage: This parameter controls the execution time of the fuzzer (in minutes). When set to the default value of 0 the fuzzer runs until the user shuts it down. Note: The execution time will be an approximate value, particularly for long running SUTs, as the controller shuts down at the end of the complete fuzzing loop in which the execution time was met.  

## <a id="NewCoverageController"></a>Section: `NewCoverageController`
Configuration information specific to the NewCoverageController.

### `NewCoverageController.primaryInputGenerator`

Value type: `<string>`

Status: Required

Usage: This parameter specifies the className or ID of the InputGeneratorModule to use as the primary input generator.

### `NewCoverageController.newCoverageInputGenerator`

Value type: `<string>`

Status: Required

Usage: This parameter specifies the className or ID of the InputGeneratorModule to use as the new coverage input generator.

### `NewCoverageController.runTimeInMinutes`

Value type: `<int>`

Status: Optional

Default value: 0

Usage: This parameter controls the execution time of the fuzzer (in minutes). When set to the default value of 0 the fuzzer runs until the user shuts it down. Note: The execution time will be an approximate value, particularly for long running SUTs, as the controller shuts down at the end of the complete fuzzing loop in which the execution time was met.  

## <a id="RunOnceController"></a>Section: `RunOnceController`
The RunOnceController does not support any custom configuration parameters.
