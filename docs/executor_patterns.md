# Executor Patterns
** NOTE: This documentation is a draft and subject to change **

[TOC]

## Goals in Refactoring Executors
- Improve maintainability by reducing the amount of complex duplicated code
- Reduce developer effort for creating new executors
- Reduce developer effort for extending executors

## Overview of Executor Module Behavior
Below are the ordered operations performed by executor modules. The abstractions we create as part of the refactor will include partial implementations of these to reduce the amount of code in the final concrete executor classes.
1. Initialize external components or runtimes
2. Capture system resources (processes, shared memory, files, pipes, environment variables)
3. Initialize runtime data structures 
   - Create executor-local copy of coverage- and comparison-maps
4. Calibrate bounded execution / timeouts
5. Deliver test case (e.g. via shared memory, file, pipe, network)
6. Execute new test case execution with bounded execution
7. Capture sut execution metrics and runteim
   - Status (crash, hang, okay)
   - Execution time
   - Coverage, comparison maps
   - Other metrics
8. Update storage entry with test case data
9. Shutdown 
   - Release system resources (processes, shared memory, files, pipes, environment variables, other?)

The VMF framework specifies an interface that executor modules implement. That API is defined across [Module.hpp](../vmf/src/framework/baseclasses/Module.hpp) [StorageUserModule.hpp](../vmf/src/framework/baseclasses/StorageUserModule.hpp)  [ExecutorModule.hpp](../vmf/src/framework/baseclasses/ExecutorModule.hpp) and it requires the implementation of the following methods:
```cpp
/* Called once per module when launching VMF */
virtual void init(ConfigInterface& config);
/* Called once per module to register fields in storage the module will read or write to */
virtual void registerStorageNeeds(StorageRegistry& registry);
/* Called once per module to register fields in storage metadata the module will read or write to */
virtual void registerMetadataNeeds(StorageRegistry& registry);
/* Called once to give executors an opporutnity to measure SUT execution time */
virtual void runCalibrationCases(StorageModule& storage, std::unique_ptr<Iterator>& iterator);
/* Called for each testcase for each testcase designated for execution */
virtual void runTestCase(StorageModule& storage, StorageEntry* entry);
```

The functions `init` and `runTestCase` implement majority of executor code; however, executors have common behavior across all functions in this API, which the refactor aims to consolidate. 

To achieve this, we introduce pattern classes which provide partial implementations of executor behavior and consolidate use of coverage data into a clearer runtime data collection class hierarchy. 

## Executor Patterns

Pattern classes provide partial implementations of behavior that subclasses can extend with more concrete semantics. For executors, we anticipate that the most common behavior that's duplicated across existing and new executor implementations are (1) the structure of delivering running testcases, (2) the execution environments, and (3) and consumption of runtime data. As a result, we abstract each of these away from the concrete executor implementations.

The Executor patterns are defined here: [ExecutorModulePattern.hpp](../vmf/src/framework/baseclasses/ExecutorModulePattern.hpp)

Most notably, this API decomposes `runTestCase` into three stages: 
1. `preDispatch`: Prep executor and SUT state prior to dispatching a testcase 
2. `DispatchTestCase`: Deliver testcase to the SUT and wait for execution to complete
3. `postDispatch`: Consume collected runtime data with updates to storage

The benefit of this decomposition is that concrete executors need not implement large portions of runTestCase, which will be inherited from the partial implementations in the pattern classes for each execution environment:
- SUTs compiled with AFL-compatible instrumentation: [AFLExecutorPattern.hpp](../vmf/src/framework/baseclasses/AFLExecutorPattern.hpp)
- Un-instrumented Binaries on Windows:
[FridaExecutorPattern.hpp](../vmf/src/framework/baseclasses/FridaExecutorPattern.hpp)

The executor patterns specific to each execution environment will implement functions necessary to interact with the execution environment such as initializing the runtime environments, initializing communication channels, killing hung SUTs, and freeing system resources.

All of VMF's controller modules provide added examples of previous usage of pattern classes: [ControllerModulePattern.hpp](../vmf/src/framework/baseclasses/ControllerModulePattern.hpp) [AnalysisController.hpp](../vmf/src/modules/common/controller/AnalysisController.hpp)
[BalancedController.hpp](../vmf/src/modules/common/controller/BalancedController.hpp)
[NewCoverageController.hpp](../vmf/src/modules/common/controller/NewCoverageController.hpp)
[IterativeController.hpp](../vmf/src/modules/common/controller/IterativeController.hpp)
[RunOnceController.hpp](../vmf/src/modules/common/controller/RunOnceController.hpp)

## Implementing & Extending Executors
The `AFL` and `Frida` executor patterns narrowly implement the behavior necessary to initialize the runtime environments, and delivery of testcases to the SUT. Management of runtime data, such as coverage and comparison maps, must be implemented by the concrete executors that extend these patterns. This design philosophy aims to ease the most common case of extending executors -- introducing new types and mechanisms for collecting runtime data. 

However, extensions to current executors or new executors are not required to use or implement pattern classes. There may be cases where executors don't fit neatly into the decomposition of `runTestCase`.
