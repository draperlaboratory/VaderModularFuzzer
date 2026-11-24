While the default modules for VMF provide well rounded fuzzing performance. There are a few best practices that when implemented along with VMF will increase fuzzing performance. For a deep dive into each module and their functionality see [core_module_configuration.md](../coremodules/core_modules_configuration.md) and [core_modules_readme.md](../coremodules/core_modules_readme.md).

## Initial Seed Selection

Good seed selection initially acts as a guide for the fuzzer as it generates new test cases. With proper generated test cases more code may be covered and as a result more bugs may be found. Additionally, proper seed selection leads to increased test case throughput, which as a result as also contributes to the overall effectiveness of a fuzzer. Generally when picking the initial seed corpus its wise to:
* Choose initial seeds that cover different points in a program.
* ***DO NOT*** cause a crash or a hang.
* Are not redundant or cover very little areas in a SUT.
* Source the seeds from known use examples or code repositories.
* If known in advance use seeds that are known to reach specific, hard-to-reach code paths.

## Target Selection

One of the most important metrics for fuzzing is the speed in which test cases are executed.  Proper target selection determines rather or not a SUT runs for extended periods of time without making substantial progress. When seeking out a target to fuzz it is important to:
* Choose a narrow-fuzz target i.e. a part of an application as opposed to the whole application.
* Identify any statefulness of a target that needs to be handled by the harness.

## Harness Creation

Harness creation is one of the most important parts of fuzzing. The other components typically have the same defaults for most common fuzzing applications. In general the *fuzzing harness* is typically responsible for:
* Managing the lifecycle of the SUT e.g. starting and resetting state and or the application for each new test cases
* Providing test cases from the fuzzer to the SUT per execution.
* Handling and returning information from the SUT to the fuzzing software.

A harness may be external to the SUT or internal i.e. compiled in as part of the SUT. That being said one of the most important parts of a successful fuzzing campaign is the creation of a proper harness. Inputs need to be provided to a target in way that it understands. 