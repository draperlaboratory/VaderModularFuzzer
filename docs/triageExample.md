# Frida Executor Triage workflow
- [Standalone Execution](#standalone-execution)
- [Understanding Coverage](#understanding-coverage)

## Standalone Execution

A VMF Frida harness can be run outside of VMF to support understanding how a test case or set of test cases behave. 

### Single test case
Here is an example of running the haystack frida SUT with a single test input (that we also just create)

```bash
cd build\\vmf_install
echo A > A.bin
test\\haystackFridaLibFuzzer\\haystack-fridaMain.exe -s Atest -i A.bin -c test/haystackFridaLibFuzzer/haystack_file.yaml
---- TEST 0 len 4 = 0:1801 us
```

The output from the driver summarizes each test to the console as: `---- TEST {test number} len {length} = {status}:{execution time} us`

*note: that The length is 4 because ECHO adds a <SPACE><CR><LF> after the message, and the execution time can vary.*

### multiple test cases

Since "interesting" or "crashing" test cases are collected into directories by VMF the runtime also allows a directory to be given as a test case input. Such as:

```bash
test\\haystackFridaLibFuzzer\\haystack-fridaMain.exe -s unique -d output\\1202_134624\\testcases\\unique -c test/haystackFridaLibFuzzer/haystack_file.yaml
---- TEST 0 len 4 = 0:1801 us
```

The Same VMF configuration file used for fuzzing should be used in standalone mode, because this file can contain options for the execution environment that should be the same between fuzzing and triage/investigation activities. 

## Understanding Coverage 

From the above example's the `-s unique` or `-s Atest` specify a <prefix> for a set of output files the VMF frida runtime will create. 

The are two types of files created. 

    1. A byte array map file with raw counts of coverage map indicies.
    2. A json file describing the execution behavior and providing necessary information from the execution instance to interpret the coverage map file. 

The meta data gives the regions used by the SUT and the blocks translated. 

```json
{
  "ranges": [
    {
      "name": "haystack-fridaMain.exe",
      "regionID": 0
    },
   ...],
   "blocks": [
    {
      "regionID": 1,
      "offset": 11203,
      "size": 2,
      "instrumented": 1,
      "symbol": "vmfFrida_runDriver",
      "symbolOffset": 147,
      "hashIndex": 0,
      "firstTest": 0
    },
    ... ]
}
```

A coverage map is indexed by an id that is an edge id. The edge id is related to the block hash id's by the function: `{edge id} = (({previous hash} - 1) ^ {current hash}) % {map size}` 

The block hash id is a xx64 hash of {rangeID,offset} and this is the value of `hashIndex`

### Utility scripts

There is a small python script helpfull for showing differences in map's. 

```bash
python ../../vmf/src/modules/windows/executor/rt/pairwiseMapSummary.py Atest.map0000 Btest.map0000
````


