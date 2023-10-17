# VMF core modules configuration #

This document provides detailed information on the configuration options for VMF core modules. A general specification of the VMF configuration file format and the top-level sections is in [/docs/configuration.md](/docs/configuration.md).

Each module may have a configuration section for keys that are specific to that module.

Initialization modules
* [`DirectoryBasedSeedGen`](#DirectoryBasedSeedGen)
* [`GramatronBasedSeedGen`](#GramatronBasedSeedGen)
* [`KleeInitialization`](#KleeInitialization)
* [`StringsInitialization`](#StringsInitialization)
* [`ServerSeedInitialization`](#ServerSeedInitialization)

Input Generator and Mutator modules
* [`GeneticAlgorithmInputGenerator`](#GeneticAlgorithmInputGenerator)
* [`MOPTInputGenerator`](#MOPTInputGenerator)

Executor and Feedback modules
* [`AFLForkserverExecutor`](#AFLForkserverExecutor)
* [`AFLFeedback`](#AFLFeedback)
* [`AFLFavoredFeedback`](#AFLFavoredFeedback)

Output modules
* [`CorpusMinimization`](#CorpusMinimization)
* [`SaveCorpusOutput`](#SaveCorpusOutput)
* [`StatsOutput`](#StatsOutput)

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

## <a id="GrammarBasedSeedGen"></a>Section: `GrammarBasedSeedGen`

Configuration information specific to the Grammar-based Seed Generator module.

### `GrammarBasedSeedGen.PDAPAth`

Value type: `<path>`

Status: Required

Usage: Relative or absolute path to the json-based pushdown automata definition for the grammar to be used during fuzzing.

### `GrammarBasedSeedGen.numTestCases`

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

### `AFLForkserverExecutor.memoryLimitInMB`

Value type: `<int>`

Status: Optional

Default value: 128

Usage: Specifies a memory limit for the SUT. A value of 0 means unlimited.

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

Value type: `<>`

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
