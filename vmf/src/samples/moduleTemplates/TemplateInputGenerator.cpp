/* =============================================================================
 * Vader Modular Fuzzer (VMF)
 * Copyright (c) 2021-2025 The Charles Stark Draper Laboratory, Inc.
 * <vmf@draper.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 (only) as 
 * published by the Free Software Foundation.
 *  
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *  
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *  
 * @license GPL-2.0-only <https://spdx.org/licenses/GPL-2.0-only.html>
 * ===========================================================================*/
#include "TemplateInputGenerator.hpp"
#include "Logging.hpp"

using namespace vmf;

/*
  This will register the mutator module with the VMF module factory, making
  it available for use via VMF configuration files.
 */
#include "ModuleFactory.hpp"
REGISTER_MODULE(TemplateInputGenerator);

/**
 * @brief Builder method to support the ModuleFactory
 * Constructs an instance of this class
 * @return Module* 
 */
Module* TemplateInputGenerator::build(std::string name)
{
    return new TemplateInputGenerator(name);
}

/**
 * @brief Initialization method
 * Reads in all configuration options for this class
 * 
 * @param config 
 */
void TemplateInputGenerator::init(ConfigInterface& config)
{
    //Call upon the config option to read any config parameters, such as
    //config.getIntParam(getModuleName(), "parameterName");

    //Look for any mutator submodules in the config file
    //Note: If you are implementing a non-mutation based input generator, then
    //omit this code
    mutators = MutatorModule::getMutatorSubmodules(config,getModuleName());

    int size = (int)mutators.size();
    if(0 == size)
    {
        throw RuntimeException("TemplateInputGenerator must be configured with at least one child mutator",
                                RuntimeException::CONFIGURATION_ERROR);
    }
}

/**
 * @brief Construct a new TemplateInputGenerator::TemplateInputGenerator object
 * 
 * @param name name of instance 
 */
TemplateInputGenerator::TemplateInputGenerator(std::string name) :
    InputGeneratorModule(name)
{
    //Not strictly neccesary, but some compilers will warn about unitialized variables otherwise
    normalTag = -1;
    testCaseKey = -1;
}

/**
 * @brief Destroy the TemplateInputGenerator::TemplateInputGenerator object
 */
TemplateInputGenerator::~TemplateInputGenerator()
{
}

/**
 * @brief Registers storage needs
 * 
 * @param registry 
 */
void TemplateInputGenerator::registerStorageNeeds(StorageRegistry& registry)
{
   normalTag = registry.registerTag("RAN_SUCCESSFULLY", StorageRegistry::READ_ONLY);
   testCaseKey = registry.registerKey("TEST_CASE", StorageRegistry::BUFFER, StorageRegistry::READ_WRITE);
}


/**
 * @brief Create one or more new test cases
 *
 * One or more new test cases should be created.  This is the main method
 * of the input generator module.
 *
 * @param storage the storage module
 */
void TemplateInputGenerator::addNewTestCases(StorageModule& storage)
{
    //Note: This template is implemented using mutator submodules, but input generators that
    //use non-mutation based strategies would not support mutator submodules.  Instead,
    //they would directly create any new test cases within this method.

    //First pick a base test case to mutate -- real algorithm implementors will want to
    //do something smarter here, but we are just picking the first test case.
    //The "normalTag" is used to limit the set of test cases to those that ran normally
    //(as opposed to those that crashed).  This tag is set by our TemplateExecutor module.
    std::unique_ptr<Iterator> entries = storage.getSavedEntriesByTag(normalTag);
    int maxIndex = entries->getSize();
    if(0 == maxIndex) {
        //This should only occur on the first run.  It either indicates that we are not receiving feedback
        //from the executor, causing it to never flag any entries to be saved (and tagged as "RAN_SUCCESSFULLY"), 
        //or VMF was configured without a seed generator, so there are no initial test cases to run.
        throw RuntimeException("No executed test cases in storage.  Either something is wrong with the executor feedback, or there is no seed generator.",
                            RuntimeException::USAGE_ERROR);
    }

    StorageEntry* baseEntry = entries->getNext(); //This is the first entry

    //Now call each of our mutators once, giving it the opportunity to add more test cases
    //More sophisticated algorithms might use a smarter approach to pick mutators to run.
    for(MutatorModule* mutator: mutators)
    {
        //Create the new storage entry, and call the mutator to mutate the testCaseKey field
        StorageEntry* newEntry = storage.createNewEntry();
        mutator->mutateTestCase(storage, baseEntry, newEntry, testCaseKey);
    }

}

/* ------------The methods below are optional for InputGenerators-------------- */

/**
 * @brief Modules using global metadata must also register fields that they intend to read or write
 *
 * Not all modules use metadata (which is summary data collected across the entries stored in storage),
 * hence this is an optional method.
 *
 * @param registry
 */
/*void TemplateInputGenerator::registerMetadataNeeds(StorageRegistry& registry)
{

}*/

/**
 * @brief Examine test case results (called prior to addNewTestCases)
 *
 * This is an optional method of InputGeneration.  InputGenerators that need
 * to look at the results of their test case runs prior to generating new test
 * cases should implement this method.  It is distinct from addNewTestCases
 * in that the storage new list has not yet been cleared when this method is called.
 *
 * Implementors of this method should be aware that configurations with more than one
 * input generator will result in StorageEntries in the fuzzing loop that were not created
 * by this input generator.  Implementors of this method that only care about their own StorageEntries
 * will need to tag or otherwise write identifying information to those StorageEntries
 * such that they can be easily identified when this method is called.
 * 
 * The default implementation of this method always returns false, indicating that the
 * input generator is not complete.  Only some input generators will have a concept of completeness,
 * those that do not should just always return false.
 * 
 * @param storage the storage module
 * @return true if the input generator is "complete", and false otherwise.
 */
/*bool TemplateInputGenerator::examineTestCaseResults(StorageModule& storage)
{
    return false;
}*/

