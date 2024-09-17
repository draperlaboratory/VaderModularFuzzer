/* =============================================================================
 * Vader Modular Fuzzer (VMF)
 * Copyright (c) 2021-2024 The Charles Stark Draper Laboratory, Inc.
 * <vmf@draper.com>
 *  
 * Effort sponsored by the U.S. Government under Other Transaction number
 * W9124P-19-9-0001 between AMTC and the Government. The U.S. Government
 * Is authorized to reproduce and distribute reprints for Governmental purposes
 * notwithstanding any copyright notation thereon.
 *  
 * The views and conclusions contained herein are those of the authors and
 * should not be interpreted as necessarily representing the official policies
 * or endorsements, either expressed or implied, of the U.S. Government.
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
#include "TemplateExecutor.hpp"
#include "Logging.hpp"

using namespace vmf;

/*
  This will register the mutator module with the VMF module factory, making
  it available for use via VMF configuration files.
 */
#include "ModuleFactory.hpp"
REGISTER_MODULE(TemplateExecutor);

/**
 * @brief Builder method to support the ModuleFactory
 * Constructs an instance of this class
 * @return Module* 
 */
Module* TemplateExecutor::build(std::string name)
{
    return new TemplateExecutor(name);
}

/**
 * @brief Initialization method
 * Reads in all configuration options for this class
 * 
 * @param config 
 */
void TemplateExecutor::init(ConfigInterface& config)
{
    //Call upon the config option to read any config parameters, such as
    //config.getIntParam(getModuleName(), "parameterName");
}

/**
 * @brief Construct a new TemplateExecutor::TemplateExecutor object
 * 
 * @param name name of instance 
 */
TemplateExecutor::TemplateExecutor(std::string name) :
    ExecutorModule(name)
{
}

/**
 * @brief Destroy the TemplateExecutor::TemplateExecutor object
 */
TemplateExecutor::~TemplateExecutor()
{
}

/**
 * @brief Registers storage needs
 * 
 * @param registry 
 */
void TemplateExecutor::registerStorageNeeds(StorageRegistry& registry)
{
    testCaseKey = registry.registerKey("TEST_CASE", StorageRegistry::BUFFER, StorageRegistry::READ_ONLY);
    crashedTag = registry.registerTag("CRASHED", StorageRegistry::WRITE_ONLY);
    normalTag = registry.registerTag("RAN_SUCCESSFULLY", StorageRegistry::WRITE_ONLY);
    hungTag = registry.registerTag("HUNG", StorageRegistry::WRITE_ONLY);
}

/**
 * @brief Method that runs the provided test case on the SUT
 * 
 * Any test results must be written to the storage entry.
 * The specific data collected will depend on the executor, but in general
 * includes information like whether the test case crashed or not and how
 * long it took to execute.
 * 
 * @param storage 
 * @param entry the entry to execute
 */
void TemplateExecutor::runTestCase(StorageModule& storage, StorageEntry* entry)
{
    //This is how to retrieve the test case buffer and size:
    //int size = entry->getBufferSize(testCaseKey);
    //char* buffer = entry->getBufferPointer(testCaseKey);

    //Real executors should now actually run the test case and collect other metrics
    //Here we will just pretend we did instead, flagging test cases that are divisible by
    //3 as crashing, and by 7 as hanging.
    if((entry->getID() % 3) == 0)
    {
        entry->addTag(crashedTag);
    }
    else if((entry->getID() % 7) == 0)
    {
        entry->addTag(hungTag);
    }
    else
    {
        entry->addTag(normalTag);
    }

}

/* ------------The methods below are optional for Executors -------------- */

/**
 * @brief Modules using global metadata must also register fields that they intend to read or write
 *
 * Not all modules use metadata (which is summary data collected across the entries stored in storage),
 * hence this is an optional method.
 *
 * @param registry
 */
/*void TemplateExecutor::registerMetadataNeeds(StorageRegistry& registry)
{

}*/

/**
 * @brief Method that runs the provided test case in callibration mode
 * This method is optional.  But it will be called once with the initial
 * seed test cases, and should be used for any callibration that requires
 * sample test cases (such as determining a reasonable execution time for a test case).
 * 
 * @param storage the reference to storage 
 * @param iterator an iterator that contains the initial seed test cases 
 */
/*void TemplateExecutor::runCalibrationCases(StorageModule& storage, std::unique_ptr<Iterator>& iterator) 
{
    while(iterator->hasNext()) 
    {
        StorageEntry* entry = iterator->getNext();
        int size = entry->getBufferSize(testCaseKey);

        //Now do whatever you need to to run the test case
    }
};*/

/**
 * @brief Method that runs the provided list of test cases on the SUT
 * 
 * This is an optional method.  The default implementation of this method
 * will simply call runTestCase() for every new entry in storage.  Executors
 * need only override this method if they do something other than run each of the
 * entries individually (for example, a batch execution capability would 
 * likely require overriding this method).
 * 
 * @param storage 
 * @param iterator 
 */
/*void TemplateExecutor::runTestCases(StorageModule& storage, std::unique_ptr<Iterator>& iterator)
{
    
}*/

