# Configuration File Format

## Introduction

The VMF configuration file is contained in one or more YAML file. These YAML files provides a structure to the configuration of the fuzzer and its modules.  Each top level YAML section (i.e. `vmfFramework`) must be contained within a single file, but otherwise the configuration parameters may be split into multiple files, as desired.  Note that all of the examples provided with VMF put the System Under Test (SUT) specific parameters into one file, and the other configuration sections in a second file.  See [getting_started.md](/docs/getting_started.md) for more information on our example configuration files and their organization.

## Top level sections

A VMF configuration file consists of the following top-level sections: 
* [`vmfVariables`](#vmfVariables) - provides default values for all variable expansions.
* [`vmfFramework`](#vmfFramework) - provides VMF framework configuration
* [`vmfModules`](#vmfModules) - provides module configuration information
* [`vmfDistributed`](#vmfDistributed) - provides distributed fuzzing configuration
* [`vmfClassSet`](#vmfClassSet) - provides a variable-based reusable list of submodules
* Any module specific parameters - these are listed in a section named by the module id or classname (see note below).

The parameters for specific core modules are documented in [Core modules README](/docs/coremodules/core_modules_readme.md) and [Core modules configuration](/docs/coremodules/core_modules_configuration.md).  

Note that configuration options for individual modules are listed under the id of the module, if one was specified, or the classname is there was no id.  

For example:
```yaml
#Config options for the StatsOutput module (this is the classname of the module, and no id was specified)
StatsOutput: 
  sendToServer: true

#Config options for the controller module
IterativeController: 
  corpusUpdateRateMins: 30
  corpusInitialUpdateMins: 10

#Config options for the storage module 
SimpleStorage:
  sortByKey: FITNESS
```

## General guidelines

By convention, keys are **inCamelCase**. Toplevel keys are prefixed with **vmf** to prevent namespace conflicts.

### Standard YAML types

The standard YAML value types are:
* `<boolean>` - true/True/TRUE or false/False/FALSE
* `<int>` - 64 bit integer with conventional encoding of base-10 (signed), octal (unsigned), hex (unsigned)
* `<float>` - floating-point approximation of real numbers. Supports multiple encodings including canonical (6.8523015e+5), exponential (685.230_15e+03), 
fixed (685_230.15), and sexagesimal (190:20:30.15). Special values for not-a-number (`.nan`), positive infinity (`.inf`), and negative infinity (`-.inf`)
* `<string>` - no special interpretation
* `<mapping>` - an unordered collection of key,value pairs
* `<list>` - an ordered collection of values (must include at least one other type)

### VMF-specific types

Value types specific to VMF:
* `<blank>` - no value is required to be specified, behavior described in comments of key
* `<enum>` - set of ints or strings representing keywords or flags (value-list in comments of key)
* `<path>` - local filesystem path to a file or directory

## <a id="vmfVariables"></a>Section: `vmfVariables`

This section provides a space to define YAML anchors that can be referenced in other sections. Configuration files can use YAML anchors and aliases to avoid repeating the same information multiple times.  This section may be omitted entirely if no YAML anchors or aliases are used in your VMF configuration.

* Anchors are specified by `&` before the anchor name
* Aliases use `*` to reference an anchor name

By convention, anchor names are in UPPER_CASE with underscores.

The following fragment shows a common use case: 

```yaml
vmfVariables:
  - &SUT_ARGV ["test/haystackSUT/haystack", "@@"]

vmfFramework:
  outputBaseDir: output
  logLevel: 1

AFLForkserverExecutor:
  sutArgv: *SUT_ARGV

StringsInitialization:
  sutArgv: *SUT_ARGV
```

## <a id="vmfFramework"></a>Section: `vmfFramework`

This section provides the basic configuration for the VMF framework. 

### `vmfFramework.outputBaseDir`

Value type: `<path>`

Status: Optional

Default value: local directory 

Usage: Specifies the directory that all VMF outputs will be put into, including log files and test case data. 

### `vmfFramework.logLevel`

Value type: `<enum>`

Status: Optional

Default value: 3 

Enum values:
* 0 - Debug
* 1 - Info
* 2 - Warning
* 3 - Error

Usage: Specifies the level of detail in log messages.

### `vmfFramework.additionalPluginsDir`

Value type: `<list of paths>`

Status: Optional

Default value: empty 

Usage: A list of directories that contain loadable VMF plugins (.so files)

## <a id="vmfModules"></a>Section: `vmfModules`  

This section provides the list of modules and their associated hierarchy that should be used in the VMF fuzzer.

### `vmfModules.storage.className`

Value type: <string>

Status: Required

Default value: empty

Usage: The classname of the StorageModule that VMF should use

### `vmfModules.controller.className`

Value type: <string>

Status: Required

Default value: empty

Usage: The classname of the top-level ControllerModule that VMF should use

### `vmfModules.controller.children`

Value type: <list>

Status: Optional (though almost always needed)

Default value: empty

Usage: The list of submodules for this controller.  Submodules can be listed individually or using a reusable list of modules called a ["classSet"](#vmfClassSet).  To list submodules individually, provide a "className" for each module (and  optionally provide an "id").

For example:
```yaml
vmfModules:
  controller:
    className: IterativeController
    children:
      - className: DirectoryBasedSeedGen
      - id: MainExecutor #optional id 
        className: AFLForkserverExecutor
```

### `vmfModules.<className or ID>.children`

Value type: <list>

Status: Optional

Default value: empty

Usage: An optional list of submodules for a particular module.  The module must be a submodule of the specified "controller" module or have parent modules that are children of the "controller" module.  If the module was declared with an "id" then "<className or ID>" will be replaced by the id.  Otherwise, "<className or ID>" will be the classname of the module.

Submodules can be listed individually or using a reusable list of modules called a ["classSet"](#vmfClassSet).  To list submodules individually, provide a "className" for each module (and  optionally provide an "id").

## <a id="vmfDistributed"></a>Section: `vmfDistributed`  

The configuration parameters needed for running VMF in distributed mode.  This section may be omitted completely for standalone mode.

### `vmfDistributed.serverURL`

Value type: <string>

Status: Required (for distributed mode)

Default value: Empty

Usage: The URL for the distibuted fuzzing server (CDMS).

### `vmfDistributed.clientName`

Value type: <string>

Status: Optional

Default value: "VMF_instance"

Usage: A human readable name for the individual VMF instance being run in distributed mode.

### `vmfDistributed.retryTimeout`

Value type: <int>

Status: Optional

Default value: 30000 (30s)

Usage: If VMF encounters a network error, this is the number of milliseconds that it will wait before trying again.  We recommend not using a small number for this value, as network errors may occur at the very start of fuzzing if a large number of test cases are found.

### `vmfDistributed.retryCount`

Value type: <int>

Status: Optional

Default value: 10

Usage: If VMF encounters a network error, this is the number of time that VMF will retry before failing.

### `vmfDistributed.taskingPollRate`

Value type: <int>

Status: Optional

Default value: 10000 (10s)

Usage: This is the number of milliseconds that VMF will sleep between requests to the server for tasking.  We recommend not setting this to a small number as this leads to bombarding the server when VMFs have not yet been tasked to do anything.

### `vmfDistributed.taskingInitialRandomDelayMax`

Value type: <int>

Status: Optional

Default value: -1 (disabled)

Usage: This parameter controls an initial random sleep for each VMF that occurs just after the VMF registers with the server, and before it asks the server for tasking.  By default this is not enabled, but it is useful to enable for distributed fuzzing configurations that include a large number of VMFs, as it minimizes the concurrent requests to the CDMS server.  Use a value of -1 to disable this feature.

## <a id="vmfClassSet"></a>Section: `vmfClassSet`

This section provides a space to define lists of submodules as YAML anchors that can be used in defining the children of a module.  This section may be omitted entirely if submodules are instead listed individually in your VMF configuration.

* Anchors are specified by `&` before the anchor name
* Aliases use `*` to reference an anchor name

By convention, anchor names are in UPPER_CASE with underscores.

The following fragment shows a common use case, defining lists of mutators.  Note that each element listed is the classname of a module.  Module ids cannot be used when using this syntax: 

```yaml
vmfClassSet:
  - &BIT_MUTATORS [AFLFlipBitMutator, AFLFlip2BitMutator, AFLFlip4BitMutator]
  - &BYTE_MUTATORS [AFLFlipByteMutator, AFLFlip2ByteMutator, AFLFlip4ByteMutator]
  - &OTHER_AFL [AFLRandomByteMutator, AFLDeleteMutator, AFLCloneMutator, AFLSpliceMutator]
```

These submodule lists can then be used to define the children of an input generator.  For example:

```yaml
  GeneticAlgorithmInputGenerator:
      children:
        - classSet: *BIT_MUTATORS
        - classSet: *BYTE_MUTATORS
        - classSet: *OTHER_AFL
```

Note that the YAML syntax supports multiple ways of defining lists.

```yaml
vmfClassSet:
  - &STANDALONE_MODULES [DirectoryBasedSeedGen, SaveCorpusOutput, StatsOutput]
  - &DISTRIBUTED_MODULES
    - ServerSeedInitialization
    - StatsOutput
    - ServerCorpusOutput
```
