# VMF 4.0.0 Migration Guide
VMF 4.0.0 includes a number of API changes that VMF Developers will need to be aware of.  Importantly, the namespace used for VMF has changed from vader to vmf, and the VaderApplication and VaderUtil classes have been renamed to VmfApplication and VmfUtil.  Additionally, a number of changes to the storage API will impact most existing modules.

Also note that the configuration file has been updated so that configuration options for the controller or storage module should be listed under the className (or id if one has been specified), just like they are for all other modules.   In VMF 3.x and before, these configuration options were listed under "controller" or "storage" instead.See [ConfigChanges](#configchanges) for more details on this change.

API changes by module type:
- [FormatterModule](#formattermodules)
- [ExecutorModule](#executormodule)
- [FeedbackModule](#feedbackmodule)
- [InputGenerator and Mutator](#inputgeneratormodule-and-mutatormodule)
- [StorageModule](#storagemodule)
- [Other API Changes](#other-api-changes)

## ConfigChanges
As an example of the configuration change for controller and storage modules, here is a VMF 3.x specification of additional parameters for the top level controller and the storage modules:
```yaml
vmfModules:
  storage: 
      className: SimpleStorage
  controller:
      className: IterativeController
      ...
controller: #Note: This is not the module classname, like it would be for other modules
  runTimeInMinutes: 1
storage: #Note: This is not the module classname, like it would be for other modules
  sortOrder: ASCENDING
```

In VMF 4.0.0, this configuration should instead be updated to:
```yaml
vmfModules:
  storage: 
      className: SimpleStorage
  controller: 
      className: IterativeController
      ...
IterativeController: #Note: This is now the module name or id, like it is for other modules
  runTimeInMinutes: 1
SimpleStorage: #Note: This is now the module name or id, like it is for other modules
  sortOrder: ASCENDING
```

## FormatterModules
This is no longer a supported module type. 	
Formatter support was causing a lot of complexity for other module types.  Formatting is also really a SUT-specific behavior that is  better addressed within the test harness itself.

## ExecutorModule
Executor modules are now users of storage, and are expected to write their outputs directly to storage (rather than storing this data internally, as in VMF 3.x).  This change allows other modules in the fuzzing loop to mamke decisions based on execution outputs.

|Old Method Signature|New Method Signature|Notes
|----|----|----|
||registerMetadataNeeds(storage, registry)|Optional method, should be implemented if reading or writing metadata|
||registerStorageNeeds()|Required to indicate the fields that are used in storage|
|runTestCase(buffer, size)|runTestCase(storage, entry)|Method to run a single test case|
||runTestCases(storage, iterator)|Optional method.  The default implementation of this method will just call runTestCase for every StorageEntry in the mutator.  This version of the method should be overriden for executors that want to perform batch execution of test cases.|
|runCalibrationCase(buffer, size)|runCalibrationCases(storage, iterator)|Calibration test cases are provided all at onces via the iterator|
|completeCalibration()||This method is no longer needed|

## FeedbackModule
In VMF 3.x, only Feedback modules could easily view execution results (and it required an awkward downcast to a specific executor subclass).  With execution results in storage, this pattern is no longer needed. 
 Feedback modules now read all of their input data from storage, rather than having a direct dependency on a particular Executor module.

|Old Method Signature|New Method Signature|Notes
|----|----|----|
|setExecutor()||This method was removed, as data should be read from storage instead.|
|bool evaluateTestCaseResults(storage, entry)|void evaluateTestCaseResults(storage, iterator)|New method provides the list of test cases to be evaluated, rather than providing them one a time.|

## InputGeneratorModule	and MutatorModule
The API changes to MutatorModule give the InputGenerator more control over mutation, to enable future features like stacked mutations.  The InputGenerator is now the one to create the new storage entry, and can specify which test case buffer to mutate.
|Old Method Signature|New Method Signature|Notes
|----|----|----|
|StorageEntry* createTestCase(StorageModule& storage, StorageEntry* baseEntry)*|void mutateTestCase( StorageModule& storage, StorageEntry* baseEntry, StorageEntry* newEntry, int testCaseKey)|Creation of newEntry now happens in Input Generator.  Additionally, the Input Generator specifies the test case field to mutate in storage.

There is additionally a change to the  InputGenerator module API to enable an InputGenerator to return a boolean value indicating that it is done with its input generation strategy.  This is an important concept for more complicated controllers that support more than one input generators.  Input generators who do not have a concept of completion should just always return false.
|Old Method Signature|New Method Signature|Notes
|----|----|----|
|void evaluateTestCaseResults(storage)|bool examineTestCaseResults(storage)|Name change to avoid implying a relationship with Feedback::evaluateTestCaseResults.  These are separate, unrelated methods.  New boolean return value to indicated completeness.

## StorageModule
The major functional change to storage is that tagging is now separated from saving.  In VMF 3.x tagging a test case would automatically save it.  In VMF 4.0.0, these concepts are separated, so tags may be used freely even on test cases that will not be saved in long term storage.

Additionally, there are a number of API changes related to this change which are detailed below.

|VMF Base Class|Old Method Signature|New Method Signature|Notes
|---|----|----|----|
|StorageModule|tagEntry(), unTagEntry(), entryHasTag(), and getEntryTagList() ||These have been removed, because tags are now accessed directly off of the StorageEntry.| 
|StorageEntry|| void addTag(int tagId)|Replace calls to storage->tagEntry(entry,myTag) with entry->addTag(myTag);
|StorageEntry||void removeTag(int tagId)|Replace calls to storage->unTagEntry(entry,myTag) with entry->removeTag(myTag)
|StorageEntry||bool hasTag(int tagId)|Replace calls to storage->entryHasTag(entry,myTag) with entry->hasTag(myTag)
|StorageEntry||std::vector<int> getTagList()|Replace calls to storage->getTagList(entry) with entry->getTaglist()|
|StorageModule|getEntriesByTag()|getSavedEntriesByTag()|This method was renamed for clarity.  Module authors will need to take care in updated existing code, as the new behavior is to return only saved entries (not all entries with a particular tag)|
|StorageModule|getEntries()|getSavedEntries()|This method was renamed for clarity.
|StorageModule|getEntryByID|getSavedEntryByID|This method was renamed for clarity.   Module authors will need to take care in updated existing code, as the new behavior is limited to retrieving saved entries by ID (not all entries).
|StorageModule|clearNewEntriesAndTags()|clearNewAndLocalEntries()|Updated due to the separation of tagging and saving (now no tags are cleared by this method).  As a reminder, this method should only be called by controller modules.|
|Iterator|reset()|resetIndex()|This method has been renamed from reset(), because it was causing a tricky-to-catch bug when reset was called on a unique_ptr<Iterator>.  Previously, accidentally calling iterator.reset() instead of iterator→reset() would clear the pointer instead of the iterator.


The following are new methods to support new capabilities in storage.
- Support for local storage entries (more information on this below)
- Convenience methods to allocate a buffer and initialize it in one step (from either another buffer or another storage entry).
- New capability to specify a default value during storage registration (int and float types only).  If a second module also specifies a default value for the same field, the value must match exactly, or there will be a storage validation error.

Local storage entries are temporary, local entries for use by algorithms that need information that is not relevant to the rest of the fuzzing loop.  These can only be used by the module that creates them, and by that modules submodules if it passes them a local entry via a method call.

|VMF Base Class|Old Method Signature|New Method Signature|Notes
|---|----|----|----|
|StorageModule||StorageEntry* createLocalEntry()|Creates a new temporary, local storage entry|
|StorageModule||void removeLocalEntry(StorageEntry*& entry);|This method is optional.  clearNewAndLocalEntries() will also automatically clear any local entries, but a specific removeLocalEntry method is included for memory management for algorithms that may need to generate a large number of local entries. |
|StorageEntry||bool isLocalEntry()|New method on storage entries that can be used to check if an entry is local.|
|StorageEntry||char* allocateAndCopyBuffer(int key, int size, char* srcBuffer)|Allocate a buffer and intialize it with the contents from srcBuffer|
|StorageEntry||char* allocateAndCopyBuffer(int key, StorageEntry* srcEntry)|Allocate a buffer and initialize it with the value from another storage entry|
|StorageEntry||bool hasBuffer(int key) const|New convenience method to check if a buffer has any contents|
|StorageRegistry||int registerIntKey(std::string keyName, accessType access,int defaultValue)|New method to register for an int value and specify a default|
|StorageRegistry||int registerFloatKey(std::string keyName, accessType access,float defaultValue)|New method to register for an float value and specify a default|

## Other API changes
All module base classes	now provide a methods getXXXSubmoduleByName.  This is new helper method to retrieve a particular submodule by name from the config file (e.g. use getControllerSubmoduleByName to retrieve a controller submodule by name).

The new VmfRand utility class provides new methods to provide access to random number generators:
- randBetween(uint64_t min, uint64_t max)
- randBelow(uint64_t limit)

Finally, VmfUtil now includes a new getCurTime() method, which is a new helper method to retrieve current time in us.