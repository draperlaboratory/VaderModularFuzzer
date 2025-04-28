# VMF 5.0.0 Migration Guide
VMF 5.0.0 includes a number of API changes that VMF Developers will need to be aware of.
These changes are organized below by class name across three sections: The Framework section includes changes to base classes, storage and utilities; the core modules section includes changes to the core set of modules shipped with VMF; and, the infrastructure section includes changes relevant to build infrastructure, CDMS, and other parts of VMF.

* [Framework](#framework)
  - [Module](#module)
  - [ModuleFactory, ConfigInterface, TestConfigInterface](#modulefactory-configinterface-testconfiginterface)
  - [StorageEntry, StorageRegistry](#storageentry-storageregistry)
  - [OSAPI, UDPMulticastAPI](#osapi-udpmulticastapi)
  - [BaseException](#baseexception)
  - [VmfRand](#vmfrand)
* [Core Modules](#coremodules)
  - [All Input Generators](#all-input-generators)
  - [RedPawnCmpLogMap](#redpawncmplogmap)
  - [AFLForkserverExecutor](#aflforkserverexecutor)
  - [AFLCoverageUtil, AFLFeedback, AFLFavoredFeedback](#aflcoverageutil-aflfeedback-aflfavoredfeedback)
  - [CorpusMinimization](#corpusminimization)
  - [SaveCorpusOutput](#savecorpusoutput)
  - [ComputeStats](#computestats)
* [Infrastructure](#infrastructure)
  - [Build Changes](#build-changes)


## Framework

### Module
This base class may now throw a runtime exception when calling `setID(int)` if an ID has already been set. Users of this API should ensure that `setID(int)` is only called once per `Module` instance.

|VMF Class|Old Method Signature|New Method Signature|Notes
|---|----|----|----|
|`Module`||`setID(int)`, `int getID()`|Added field, getter and setter for an instance-specific module identifer.| 

### ModuleFactory, ConfigInterface, TestConfigInterface
We've added an API to find modules by their ID.

|VMF Class|Old Method Signature|New Method Signature|Notes
|---|----|----|----|
|`ModuleFactory`||`std::string getModuleName(int)`|Added method to search for module by ID|
|`ConfigInterface`||`virtual std::string getModuleName(int)`|Added a virtual function to search for module by ID|
|`TestConfigInterface`||`virtual std::string getModuleName(int)`|Added a virtual function to search for module by ID|

### StorageEntry, StorageRegistry, 
Storage now supports unsigned 64-bit values. The `StorageEntry` and `StorageRegistry` APIs have been expanded with the following functions in support of that:

|VMF Class|Old Method Signature|New Method Signature|Notes
|---|----|----|----|
|`StorageEntry`||`setValue(int, unsigned long long)`|Added method to store 64-bit values|
|`StorageEntry`||`unsigned long long getU64Value(int)`|Added method to fetch 64-bit values|
|`StorageEntry`||`unsigned long long incrementU64Value(int)`|Added method to increment 64-bit values|
|`StorageRegistry`||`int registerU64Key(std::string, accessType, unsigned long long)`|Added method to register 64-bit field in storage|
|`StorageRegistry`||`std::vector<unsigned long long> getU64KeyDefaults()`|Added method to return storage's default value for 64-bite fields|

### OSAPI, UDPMulticastAPI
An outcome of Windows support is our OS API and UDP Multicast abstraction layers, which provide platform agnostic wrappers to common OS-provided and UDP functions. 

|VMF Class|Old Method Signature|New Method Signature|Notes
|---|----|----|----|
|`OSAPI`||`static OSAPI& instance()`|Returns a singleton instance|
|`OSAPI`||`void* openDLL(std::string)`|Loads the provided shared library by name|
|`OSAPI`||`closeDLL(void*)`|Closes the provided shared library|
|`OSAPI`||`int getOption(int, char*, const char*)`|Parses command-line options using linux getopt-style parsing. See: https://www.man7.org/linux/man-pages/man3/getopt.3.html|
|`OSAPI`||`std::string getOptionArg()`|Call after getOption to retrieve the argument associated with the option|
|`OSAPI`||`int getProcessID()`|Returns the current process ID|
|`OSAPI`||`std::string getHostname()`|Returns the host name of the current system|
|`OSAPI`||`std::string getExecutablePath()`|Retrieve the path of the currently running executable|
|`OSAPI`|`bool VmfUtil::commandLineZip(std::string, std::string)`|`bool OSAPI::commandLineZip(std::string, std::string)`|Moved from VmfUtil to OSAPI|
|`OSAPI`|`bool VmfUtil::commandLineUnzip(std::string, std::string)`|`bool OSAPI::commandLineUnzip(std::string, std::string)`|Moved from VmfUtil to OSAPI|
|`UDPMulticastAPI`||`static UDPMulticastAPI* instance()`|Returns a UDP multicast socket instance; buildSocket must be called on the instance to configure it prior to use|
|`UDPMulticastAPI`||`void buildSocket(std::string, int)`|Configures the socket; this must be called prior to readData|
|`UDPMulticastAPI`||`int readData(char*, int)`|Reads data from the socket|

### BaseException

`BaseException` now internally uses `std::string` instead of `char*`

|VMF Class|Old Method Signature|New Method Signature|Notes
|---|----|----|----|
|`BaseException`|`BaseException(const char*)`|`BaseException(std::string)`||
|`BaseException`|`setReason(const char*)`|`setReason(std::string)`||
|`BaseException`|`const char* getReason()`|`std::string getReason()`||

### VmfRand

`VmfRand` now uses `unsigned long` and `int`

|VMF Class|Old Method Signature|New Method Signature|Notes
|---|----|----|----|
|`VmfRand`|`uint64_t randBetween(uint64_t, uint64_t)`|`unsigned long randBetween(unsigned long, unsigned long)`||
|`VmfRand`|`uint64_t randBelow(uint64_t)`|`unsigned long randBelow(unsigned long)`||
|`VmfRand`||`int randBetween(int, int)`||
|`VmfRand`||`int randBelow(int)`||
|`VmfRand`||`int randBelowExcept(int, int)`||

## Core Modules
### All Input Generators
We've added support for the `SaveCorpusOutput` module to optionally output metadata for each interesting test case. Consequentially, input generators must now write this field. Input generators that don't use additional mutators may self identify by using the its own ID (the input-generator's ID) as the source for mutation.

- Input generators must register the `MUTATOR_ID` storage key as `WRITE_ONLY` or `READ_WRITE`
- Input generators must set `MUTATOR_ID` for each test case based on the module used for mutation

For example, this can be done by, 
adding the following code to the input generator's call to `registerStorageNeeds(...)`:
```
mutatorIdKey = registry.registerIntKey("MUTATOR_ID", StorageRegistry::WRITE_ONLY, 1);
```

and code similar to the following to its call to `addNewTestCases(...)`
```
StorageEntry* newEntry = ... // Feteching a storage entry
mutator = ... // Fetching a mutator
... // Apply mutation
newEntry->setValue(mutatorIdKey, mutator->getID()); // Label the test case with the mutator's ID

```

### RedPawnCmpLogMap
AFL++ changed the structure of the Cmplog instrumentation embedded in SUTs that VMF reads. As a result, we've updated our internal structures to match the new version. SUTs with cmplog instrumentation must be recompiled with AFL++ v4.30 instrumentation.

Another unrelated change added this module to the `vmf` namespace.

### AFLForkserverExecutor
In support of multiple instances of the AFLForkserverExecutor, it now saves a calibrated timeout as a static member field (`calibrated_timeout`), which other instances may read without rerunning calibration.

This module also no longer writes `MAP_SIZE` to storage metadata. Modules that depend on reading the map size must instead become map-size agnostic.

### AFLCoverageUtil, AFLFeedback, AFLFavoredFeedback
In support of the Windows build, these modules are now platform agnostic and moved to the `common` subdirectory for modules (formerly under `linux`).
Further, `AFLCoverageUtil` is now under the `feedback` subdirectory.
- `vmf/src/modules/linux/executor/AFLCoverageUtil*` -> `vmf/src/modules/common/feedback/AFLCoverageUtil*`
- `vmf/src/modules/linux/feedback/AFLFavoredfeedback*` -> `vmf/src/modules/common/feedback/AFLFavoredFeedback*`
- `vmf/src/modules/linux/feedback/AFLfeedback*` -> `vmf/src/modules/common/feedback/AFLFeedback*`

### CorpusMinimization
In support of the Windows build, this module is now platform agnostic and moved to the `common` subdirectory for modules (formerly under `linux`).
- `vmf/src/modules/linux/output/CorpusMinimization*` -> `vmf/src/modules/common/output/CorpusMinimization*`

Further, this module no longer reads `MAP_SIZE` from storage metadata. As a consequence, any modules writing this field may incur an error during startup.

### SaveCorpusOutput
We've added a feature that records testcase metadata, currently limited to mutator identification. This data is written to a file that matches the testcase file name appended with "_metadata" (`<testcase>_metadata`). In support for this, `SaveCorpusOutput` now registers the storage key `MUTATOR_ID` as `READ_ONLY`, expecting input generators to populate that field. VMF will throw an error if no configured modules write this field.

This feature is enabled by adding the following configuration option:
```
SaveCorpusOutput:
  recordTestMetadata: true
```

### ComputeStats
`ComputeStats` now registers the total number of test cases executed as an unsigned 64-bit field.

## Infrastructure
### Build Changes
- VMF no longer explicitly builds with `g++` and will instead use the system-configured compiler by default.
