# Scenario File

## Spec

Scenario files are JSON in the following format:

```typescript
type ScenarioFile = {
    title: String;
    type: "fuzzer" | "analyzer" | "minimizer";
    configurationFiles: String[];
    seedFiles: String[]
}[];

```

`configurationFiles` and `seedFiles` are names of files that are already uploaded to CDMS. When uploaded, CDMS will look for all listed configuration files and seed files. If any do not exist, CDMS will gracefully inform the user which files are missing. If not, the scenario will generated on the server.

Optionally, the root list can be omitted, for a Scenario file containing a single scenario.

### Example

```json
[{
  "title": "magicBytes RedPawn",
  "type": "fuzzer",
  "configurationFiles": ["distributedBasicModules.yaml", "haystack.yaml"],
  "seeds": ["input1.bin", "input2.bin", "input3.bin"]
}]
```