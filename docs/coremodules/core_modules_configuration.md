# VMF core modules configuration #

This document provides detailed information on the configuration options for VMF core modules. A general specification of the VMF configuration file format and the top-level sections is in [/docs/configuration.md](../configuration.md).

Each module may have a configuration section for keys that are specific to that module.

Initialization modules
* [`DirectoryBasedSeedGen`](#section-directorybasedseedgen)
* [`GramatronBasedSeedGen`](#section-gramatronbasedseedgen)
* [`ServerCorpusInitialization`](#section-servercorpusinitialization)
* [`ServerSeedInitialization`](#section-serverseedinitialization)
* [`TrivialSeedInitialization`](#section-trivialseedinitialization)
* [`DictionaryInitialization`](#section-dictionaryinitialization)
* [`KleeInitialization`](#section-kleeinitialization)
* [`StringsInitialization`](#section-stringsinitialization)

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
* [`ServerCorpusMinOutput`](#section-servercorpusminoutput)
* [`ServerCorpusOutput`](#section-servercorpusoutput)
* [`StatsOutput`](#section-statsoutput)

Controller modules
* [`Parameters Common to All Controller Modules`](#section-parameters-common-to-all-controller-modules)
* [`AnalysisController`](#section-analysiscontroller)
* [`IterativeController`](#section-iterativecontroller)
* [`NewCoverageController`](#section-newcoveragecontroller)
* [`RunOnceController`](#section-runoncecontroller)

Mutator modules
* [`DictionaryMutator`](#section-dictionarymutator)
* [`AFLCloneMutator`](#section-aflclonemutator)
* [`AFLDeleteMutator`](#section-afldeletemutator)
* [`AFLFlipBitMutator`](#section-aflflipbitmutator)
* [`AFLFlipByteMutator`](#section-aflflipbytemutator)
* [`AFLFlip2BitMutator`](#section-aflflip2bitmutator)
* [`AFLFlip2ByteMutator`](#section-aflflip2bytemutator)
* [`AFLFlip4BitMutator`](#section-aflflip4bitmutator)
* [`AFLFlip4ByteMutator`](#section-aflflip4bytemutator)
* [`AFLRandomByteAddSubMutator`](#section-aflrandombyteaddsubmutator)
* [`AFLRandomByteMutator`](#section-aflrandombytemutator)
* [`AFLSpliceMutator`](#section-aflsplicemutator)
<!-- * [`GramatronMutator`](#section-grammatronmutator) -->
* [`GramatronGenerateMutator`](#section-gramatrongeneratemutator)
* [`GramatronRandomMutator`](#section-gramatronrandommutator)
* [`GramatronRecursiveMutator`](#section-gramatronrecursivemutator)
* [`GramatronSpliceMutator`](#section-gramatronsplicemutator)
* [`StackedMutator`](#section-stackedmutator)

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


### Configuration example
```yaml
GramatronBasedSeedGen:
  numTestCases: 20s
  PDAPAth: path/to/pda.json
```

## <a id="ServerCorpusInitialization"></a>Section: `ServerCorpusInitialization`

Initialize using the server-provided corpus -- distinct from ServerSeedInitialization in
that the whole corpus is always retrieved from the server. This is useful for VMF
configurations that minimize the corpus.

### `ServerCorpusInitialization.writeServerURL`

Value type: `<bool>`

Status: Optional

Default value: `true`

Usage: Stores a copy of the URL associated with the file in storage

### Configuration example
```yaml
ServerCorpusInitialization:
  writeServerURL: true
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
  writeServerURL: true
```

## <a id="TrivialSeedInitialization"></a>Section: `TrivialSeedInitialization`

This initialization module will initialize the storage module with a single string that is hard-coded in order to provide a trivial input into the SUT.  This module has no configuration settings.

## <a id="DictionaryInitialization"></a>Section: `DictionaryInitialization`

Configuration information specific to the DictionaryInitialization module. 

### `DictionaryInitialization.sutArgv`

Value type: `<list of strings>`

Status: Required

Usage: The SUT to extract the strings from using the linux `strings` command.  Any blank strings that are extacted as skipped over during dictionary generation.

### Configuration example
```yaml
DictionaryInitialization:
  sutArgv: test/haystackSUT/haystack.bc
```

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

Configuration information specific to the MOPTInputGenerator module.  Can be used with any mutator module as a submodule.

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

Configuration information specific to the RedPawn Input Generator module.  Can be used with the following submodules:

* [`AFLForkserverExecutor`](#section-aflforkserverexecutor) for `colorizationExecutor`
* [`AFLForkserverExecutor`](#section-aflforkserverexecutor) for `cmplogExecutor`

### `RedPawnInputGenerator.maxTimePerSeedInSeconds`

Value type: `<int>`

Status: Optional

Default Value: 600

Usage: Configures the maximum amount of wallclock time that will be spent doing RedPawn analysis from the same seed testcase. When the maximum amount of time is reached, RedPawn discards the seed testcase and moves on to the next. The value of 0 can be used to indicate no time limit. The default is 10 minutes (600 seconds).

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

### `RedPawnInputGenerator.skipStaticLogEntries`

Value type: `<bool>`

Status: Optional

Default Value: `true`

Usage: This is an optimization that skips some expensive RedPawn analysis for log entries
whose comparisons are unaffected by a colorized input.

### `RedPawnInputGenerator.alwaysCreatePlusMinusOne`

Value type: `<bool>`

Status: Optional

Default Value: `false`

Usage: Force RedPawn to create +/- 1 variations to values it creates. When compare types (eg., less than, greater than) are available those can be used instead which creates less total testcases. When using standard AFL CMPLOG, this should be left as false because the compare types will be available.

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

### `RedPawnInputGenerator.useDirectStringTransform`

Value type: `<bool>`

Status: Optional

Default Value: `true`

Usage: enables the direct string transform

### `RedPawnInputGenerator.useToUpperStringTransform`

Value type: `<bool>`

Status: Optional

Default Value: `false`

Usage: enables the ToUpper (uppercase characters) string transform

### `RedPawnInputGenerator.useToLowerStringTransform`

Value type: `<bool>`

Status: Optional

Default Value: `false`

Usage: enables the ToLower (lowercase characters) string transform

### Configuration example
```yaml
RedPawnInputGenerator:
  colorizeMaxExecs: 2000
  batchSize: 2000
  skipStaticLogEntries: true
  useDirectTransform: true
  useReverseBytesTransform: true
  useOffsetTransform: true
  useFactorTransform: true
  useXORTransform: false
  useDirectStringTransform: true
  useToUpperStringTransform: false
  useToLowerStringTransform: false
```

## <a id="AFLForkserverExecutor"></a>Section: `AFLForkserverExecutor`

Configuration information specific to the AFL Forkserver Executor module. 

### `AFLForkserverExecutor.sutArgv`

Value type: `<list of strings>`

Status: Required

Usage: A list (array) of strings that represent the command line with arguments for the system under test (SUT). The first parameter must be the application itself, either with a relative path or an absolute path. Other command-line arguments for the application are given in order as separate strings. The special argument `"@@"` is used when test case data should be passed from the fuzzer to the SUT in a file. The `"@@"` will be replaced at runtime with the filename.

### `AFLForkserverExecutor.timeoutInMs`

Value type: `<int>`

Status: Optional

Default: Computed based on initial seeds

Usage: Specifies the time in milliseconds that VMF will use to determine whether execution of the SUT has hung.  This is an optional parameter, and when not specified the executor will instead automatically compute a timeout value based on the initial seeds. Care must be taken when manually specifying this value, as a timeout that is too short will result in test cases being erroneously identified as hanging.

### `AFLForkserverExecutor.ignoreHangs`

Value type: `<bool>`

Status: Optional

Default: false

Usage: Specifies to ignore hanging test cases during fuzzing.  While hanging testcases may be executed and marked as hanging they will not be marked as producing new coverage.  This will be overriden to false if `timeoutInMs` is specified in the user-provided configuration.  All testcases that hang in this mode will additionally be marekd as `INCOMPLETE`.

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

### `AFLForkserverExecutor.enableAFLDebug`

Value type: `<boolean>`

Status: Optional

Default value: `false`

Usage: Sets the `AFL_DEBUG` environment variable which causes AFL instrumentation to print more debug information on stderr. Can be useful for debugging instrumentatation issues, such as map size, shared memory or cmplog issues. Use with `debugLog` to inspect it.

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

### `AFLForkserverExecutor.enableCoreDumpCheck`

Value type: `<boolean>`

Status: Optional

Default value: `true`

Usage: When enabled, the forkserver requires core dump notifications to not be sent to an external utility.  This is important for speed and to prevent crashes from being misinterpreted as timeouts.  Typically this setting should not be changed, but is is provided because it is not always possible to configure core dump notifications in all environments, due to permission issues.

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

Configuration information specific to the CorpusMinimization module, which periodically scans the testcase corpus and removes testcases that are not contributing to coverage.  Can be used with [`ServerCorpusMinOutput`](#section-servercorpusminoutput).

### `CorpusMinimization.frequencyInMinutes`

Value type: `<int>`

Status: Optional

Default value: 30

Usage: This parameter specifies how often the module is scheduled, in minutes. It reruns all the testcases during each culling, so the frequency should not be set too low.

### Configuration example
```yaml
CorpusMinimization:
  frequencyInMinutes: 30
```

### `CorpusMinimization.minimizeOnShutdown`

Value type: `<bool>`

Status: Optional

Default value: true

Usage: This parameter controls whether corpus minimization is performed when VMF receives a signal to shutdown. 


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

### `SaveCorpusOutput.recordTestMetadata`

Value type: `<bool>`

Status: Optional

Default value: false

Usage: This parameter controls whether the module creates files per saved test case that
contain metadata such as the mutators, notable input generators, etc. used to generate
that test case. Seed test cases are labeled with the configuration's controller module
name.

### Configuration example
```yaml
SaveCorpusOutput:
  recordTestMetadata: true
```


## <a id="ServerCorpusMinOutput"></a>Section: `ServerCorpusMinOutput`

This module transmits a minimized corpus to the server. This module only makes sense in
the context of a controller that solely performs corpus minimization on the common corpus
(e.g. AnalysisController).

### Accepted Submodules

This module accepts the following children submodules:

* [CorpusMinimization](#section-corpusminimization)

### Example Configuration
```yaml
  ServerCorpusMinOutput:
    children:
      - className: CorpusMinimization
```

## <a id="ServerCorpusOutput"></a>Section: `ServerCorpusOutput`

This module transmits all corpus data, including any tags, to the server. Test cases
tagged with "SERVER_TC" are excluded.

### `ServerCorpusOutput.serverDelayTimeinSecs`

Value type: `<int>`

Status: Optional

Default value: 30

Usage: Send test cases to the server at this interval.

### `ServerCorpusOutput.serverDelayOverrideCount`

Value type: `<int>`

Status: Optional

Default value: -1

Usage: Override serverDelayTimeInSecs if the configured number of test cases have been
found, and send test cases immediately. A value of -1 will disable this override.

## <a id="StatsOutput"></a>Section: `StatsOutput`

Configuration information specific to the StatsOutput module. 

### `StatsOutput.sendToServer`

Value type: `<bool>`

Status: Optional

Default value: false

Usage: This parameter controls whether the module outputs runtime statistics to the local console or to a distributed fuzzing CDMS server. If the value is `true` the data will be sent to the server address specified in [`vmfDistributed.serverURL`](../configuration.md#vmfDistributed)

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


### `controller.runTimeInMinutes`

Value type: `<int>`

Status: Optional

Default value: 0

Usage: The runtime in minutes for executing the fuzzing session.  If not set the fuzzing session will continue until manually exited by the user.

## <a id="AnalysisController"></a>Section: `AnalysisController`
The AnalysisController does not support any custom configuration parameters.

## <a id="NewCoverageController"></a>Section: `BalancedController`
The BalancedController can be configured with any number of InputGenerator modules and balances their use.

### `BalancedController.balanceMetric`

Value type: `<string>`

Status: Optional

Default value: "time"

Usage: Sets the metric by which the InputGenerators wills be balanced. The three available options are "time", "uses", or "testcasesGenerated". Each cycle of the controller, the InputGenerator that is behind the most by the specified metric will be selected for that cycle.

### `BalancedController.epochLengthInMinutes`

Value type: `<int>`

Status: Optional

Default value: 30

Usage: Sets the length of an epoch, which is the period of time under which stats are collected and balanced within. Epochs help address a "catch-up" problem that can occur when some input generators can't be used and therefore fall behind on stats by large amounts. When suddenly they become available, they become selected exclusively until parity is made among all input generators. The value of 0 can be used to disable epochs, which removes this feature and makes the balancing time window the entire run.

## <a id="IterativeController"></a>Section: `IterativeController`
The IterativeController does not support any custom configuration parameters.


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

### Configuration example
```yaml
NewCoverageController:
  primaryInputGenerator: MOPT
  newCoverageInputGenerator: RedPawnInputGenerator
```

## <a id="RunOnceController"></a>Section: `RunOnceController`
The RunOnceController does not support any custom configuration parameters.



## <a id="DictionaryMutator"></a>Section: `DictionaryMutator`
Configuration information specific to the DictionaryMutator.

### `DictionaryMutator.dictionaryPaths`

Value type: `<list of strings>`

Status: Optional

Usage: This parameter specifies the paths to the list of tokens to fuzz with.  When not specified, this module must be run in a configuration that contains a DictionaryInitialization module to provide dictionary inputs.  Blank tokens are skipped during load of these dictionaries.


### Configuration example
```yaml
DictionaryMutator:
  dictionaryPaths: test/unittest/inputs/DictionaryMutator/png.dict
```


## <a id="AFLCloneMutator"></a>Section: `AFLCloneMutator`

This mutator does not take any configuration values.

## <a id="AFLDeleteMutator"></a>Section: `AFLDeleteMutator`

This mutator does not take any configuration values.

## <a id="AFLFlipBitMutator"></a>Section: `AFLFlipBitMutator`

This mutator does not take any configuration values.

## <a id="AFLFlipByteMutator"></a>Section: `AFLFlipByteMutator`

This mutator does not take any configuration values.

## <a id="AFLFlip2BitMutator"></a>Section: `AFLFlip2BitMutator`

This mutator does not take any configuration values.

## <a id="AFLFlip2ByteMutator"></a>Section: `AFLFlip2ByteMutator`

This mutator does not take any configuration values.

## <a id="AFLFlip4BitMutator"></a>Section: `AFLFlip4BitMutator`

This mutator does not take any configuration values.

## <a id="AFLFlip4ByteMutator"></a>Section: `AFLFlip4ByteMutator`

This mutator does not take any configuration values.

## <a id="AFLRandomByteAddSubMutator"></a>Section: `AFLRandomByteAddSubMutator`

This mutator does not take any configuration values.

## <a id="AFLRandomByteMutator"></a>Section: `AFLRandomByteMutator`

This mutator does not take any configuration values.

## <a id="AFLSpliceMutator"></a>Section: `AFLSpliceMutator`

This mutator does not take any configuration values.

## <a id="GramatronGenerateMutator"></a>Section: `GramatronGenerateMutator`

This mutator does not take any configuration values.

## <a id="GramatronRandomMutator"></a>Section: `GramatronRandomMutator`

This mutator does not take any configuration values.

## <a id="GramatronRecursiveMutator"></a>Section: `GramatronRecursiveMutator`

This mutator does not take any configuration values.

## <a id="GramatronSpliceMutator"></a>Section: `GramatronSpliceMutator`

This mutator does not take any configuration values.

## <a id="StackedMutator"></a>Section: `StackedMutator`

Configuration information specific to the `StackedMutator` module.  Must be used with the following submodule:

* A list of desired mutators for composing in a mutation stack for `classSet`.  For example:  
```yaml
children:
    - classSet: [AFLFlipBitMutator, AFLFlip2BitMutator, AFLFlip4BitMutator]
```

This set of mutators is not verified for compatability of mutation strategies between all members.


### `StackedMutator.mutatorSelector`

Value type: `<str>`

Status: Optional

Default value: `staticMutatorSelector`

Usage: This parameter determines the method for selecting mutators during stack generation.  It currently supports 3 options:

* `staticMutatorSelector`
  * Stacks generated with this will follow the same order as those provided in the `classSet`
* `uniformMutatorSelector`
  * Mutators will be choosen according to a uniform random distribution from the `classSet` provided by the user
* `WeightedRandomSelector`
  * Mutators will be choosen according to a weighted random distribution from the `classSet` provided by the user according to a distribution also proided by the user, see [`StackedMutator.mutatorSelectionDistribution`](#stackedmutatormutatorselectiondistribution)

The default value will assume that the `classSet` provided by the user defines the mutation stack the user wishes to use for all testcase generation.

### `StackedMutator.randomStackSize`

Value type: `<bool>`

Status: Optional

Default value: `false`

Usage: This parameter determines whether to randomize stack size for the stacked mutator during application to a specific test case.  It will randomly select between 1 and the `stackSize` value.  It will pick from the same list of mutators in the same order of mutator selection randomization is not enabled and will randomly select the randomly choosen stack size number of mutators if selection is randomized

### `StackedMutator.stackSize`

Value type: `<int>`

Status: Optional

Default value: length of the list of mutators provided

Usage: An optional choice for length of mutation stack generated during testcase execution time.  When mutator randomization is not enabled it will cyclically select from the pool of mutators provided by the user in the same order provided by the user.  For example, if the user provides:

```yaml
children:
    - classSet: [AFLFlipBitMutator, AFLFlip2BitMutator, AFLFlip4BitMutator]
```

with `stackSize: 4` then it will produce mutation stack: `{AFLFlipBitMutator, AFLFlip2BitMutator, AFLFlip4BitMutator, AFLFlipBitMutator}` at all test case mutation times.

### `StackedMutator.mutatorSelectionDistribution`

Value type: `<std::vector<float>>`

Status: Optional

Default value: a vector of floats the same size as the number of mutators provided by the user representing a uniform probability distribution

Usage: An optional parameter to specify the selection distribution of mutators during randomized selection of mutators.  It must be the same size as the number of mutators and each index must correspond to the desired probability of selecting mutator `i` in the list of provided mutators.  For example, if a user provides the following list of mutators:


```yaml
children:
    - classSet: [AFLRandomByteMutator, AFLDeleteMutator, AFLCloneMutator, AFLSpliceMutator]
```

with `mutatorSelectionDistribution: [0.125, 0.125, 0.25, 0.5]` and mutator selection randomization enabled then the chances of selecting `AFLRandomByteMutator` at position `i` in the mutation stack generated at test case mutation time will be `0.125` or 12.5%.  Similarly `AFLDeleteMutator` will be 12.5%, `AFLCloneMutator` 25%, and `AFLSpliceMutator` 50%.

If specified without either stack size or mutator selection randomization enabled a warning will be issued that the specified distribution may not be followed during fuzzing.

### Configuration example
```yaml
vmfModules:
  storage: #a storage module must be specified
      ...
  controller: #a controller module must be specified
      ...
  GeneticAlgorithmInputGenerator:
      children:
        - id: baseStack
          className: StackedMutator

  baseStack:
    children:
      - classSet: [AFLFlipBitMutator, AFLFlip2BitMutator, AFLFlip4BitMutator]

# Modules-specific parameters
#(The SUT-specific portions of these all defined using YAML anchors)
baseStack:
  randomStackSize: false
  stackSize: 3
  mutatorSelectionDistribution: [0.333, 0.333, 0.334]
```