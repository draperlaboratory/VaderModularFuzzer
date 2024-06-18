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
#include "RunOnceController.hpp"
#include "Logging.hpp"

using namespace vmf;

#include "ModuleFactory.hpp"
REGISTER_MODULE(RunOnceController);

/**
 * @brief Builder method to support the ModuleFactory
 * Constructs an instance of this class
 * @return Module* 
 */
Module* RunOnceController::build(std::string name)
{
    return new RunOnceController(name);
}

/**
 * @brief Initialization method
 * Reads in all configuration options for this class
 * 
 * @param config 
 */
void RunOnceController::init(ConfigInterface& config)
{
    ControllerModule::init(config);

    executor = nullptr;
    feedback = nullptr;

    //An exception will be thrown if more than one module is specified for modules
    //types for which only a single instance is supported
    executor = ExecutorModule::getExecutorSubmodule(config, getModuleName());
    feedback = FeedbackModule::getFeedbackSubmodule(config, getModuleName());
    
    //For these module types, multiple module instances are supported
    outputs = OutputModule::getOutputSubmodules(config, getModuleName());
    initializations = InitializationModule::getInitializationSubmodules(config, getModuleName());
    inputGenerators = InputGeneratorModule::getInputGeneratorSubmodules(config, getModuleName());

    if((nullptr!=feedback))
    {
        //An executor must be specified to use a feedback module
        if(nullptr==executor)
        {
            throw RuntimeException("FeedbackModule cannot be specified without an ExecutorModule",
                                   RuntimeException::CONFIGURATION_ERROR);
        }
    }

    //If there is an executor module, then a feedback module must be provided
    if((nullptr!=executor) && (nullptr==feedback))
    {
            throw RuntimeException("ExecutorModule cannot be specified without an FeedbackModule",
                                   RuntimeException::CONFIGURATION_ERROR);
    }

}

/**
 * @brief Construct a new Iterative Controller object
 * 
 * @param name the name o the module
 */
RunOnceController::RunOnceController(
    std::string name) :
    ControllerModule(name),
    initializations()
{

}

RunOnceController::~RunOnceController()
{

}

void RunOnceController::registerStorageNeeds(StorageRegistry& registry)
{
    ControllerModule::registerStorageNeeds(registry);
}

void RunOnceController::registerMetadataNeeds(StorageRegistry& registry)
{
    totalNumTestCasesMetadataKey = registry.registerKey("TOTAL_TEST_CASES", StorageRegistry::INT, StorageRegistry::WRITE_ONLY);
}


bool RunOnceController::run(StorageModule& storage, bool firstPass)
{
    //Run any initialization modules
    for(InitializationModule* m: initializations)
    {
        m->run(storage);
    }

    //Run any input generator modules
    for(InputGeneratorModule* m: inputGenerators)
    {
        m->addNewTestCases(storage);
    }

    //If there is an executor, callibrate and run it
    if(nullptr!=executor)
    {
        calibrate(storage);
        executeTestCases(firstPass, storage);
    }

    //Let the input generators evaluate any results
    for(InputGeneratorModule* m: inputGenerators)
    {
        //Ignore the results, as we don't care if the input generators are done, since they only run once anyway
        m->examineTestCaseResults(storage);
    }

    //Run any output modules
    for(OutputModule* m: outputs)
    {
        m->run(storage);
    }

    //Now clear the new list.
    //This will also delete any discarded new entries
    storage.clearNewAndLocalEntries();

    return true; //execution always finishes after one fuzzing loop run
}


/**
 * @brief Calls upon the executor module to calibrate
 * Each of the initial test cases in storage will be passed to the executor
 * for callibration.  
 * Subclasses may override this method to provide different behavior.
 * 
 * @param storage 
 */
void RunOnceController::calibrate(StorageModule& storage)
{
    //Provide each test case in the initial corpus to the executor for calibration
    
    //Now run each test case
    std::unique_ptr<Iterator> storageIterator = storage.getNewEntries();
    if(storageIterator->getSize()>0)
    {
        executor->runCalibrationCases(storage, storageIterator);
    }
    else
    {
        LOG_WARNING << "There are no seed test cases in storage to callibrate the executor with.";
    }
}


/**
 * @brief Helper method to execute all the new test cases
 * The executor will be called to run each one, and the feedback module will
 * be called to evaluate the results.
 * 
 * Subclasses may override this method to provide different behavior.
 * 
 * @param firstPass true if this is the first pass through the fuzzing loop
 * @param storage the storage module
 */
void RunOnceController::executeTestCases(bool firstPass, StorageModule& storage)
{
    std::unique_ptr<Iterator> storageIterator = storage.getNewEntries();

    //Update TOTAL_TEST_CASES metadata
    newCasesCount = storageIterator->getSize();
    StorageEntry& metadata = storage.getMetadata();
    int totalCasesCount =  metadata.getIntValue(totalNumTestCasesMetadataKey) + newCasesCount;
    metadata.setValue(totalNumTestCasesMetadataKey, totalCasesCount);

    executor->runTestCases(storage, storageIterator);
    storageIterator->resetIndex();
    feedback->evaluateTestCaseResults(storage, storageIterator);
    
}


