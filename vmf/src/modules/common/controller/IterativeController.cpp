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
#include "IterativeController.hpp"
#include "Logging.hpp"

using namespace vmf;

#include "ModuleFactory.hpp"
REGISTER_MODULE(IterativeController);

/**
 * @brief Builder method to support the ModuleFactory
 * Constructs an instance of this class
 * @return Module* 
 */
Module* IterativeController::build(std::string name)
{
    return new IterativeController(name);
}

/**
 * @brief Initialization method
 * Reads in all configuration options for this class
 * 
 * @param config 
 */
void IterativeController::init(ConfigInterface& config)
{
    ControllerModule::init(config);
    runTimeMinutes = config.getIntParam(getModuleName(),"runTimeInMinutes", 0);

    executor = nullptr;
    inputGenerator = nullptr;
    feedback = nullptr;

    //An exception will be thrown if more than one module is specified for modules
    //types for which only a single instance is supported
    executor = ExecutorModule::getExecutorSubmodule(config, getModuleName());
    feedback = FeedbackModule::getFeedbackSubmodule(config, getModuleName());
    inputGenerator = InputGeneratorModule::getInputGeneratorSubmodule(config, getModuleName());
    
    //For these module types, multiple module instances are supported
    outScheduler.setOutputModules(OutputModule::getOutputSubmodules(config, getModuleName()));
    initializations = InitializationModule::getInitializationSubmodules(config, getModuleName());

    //Validate the configuration
    if(nullptr == executor)
    {
        throw RuntimeException("IterativeController requires an ExecutorModule",
                                RuntimeException::CONFIGURATION_ERROR);
    }

    if(nullptr == feedback)
    {
        throw RuntimeException("IterativeController requires a FeedbackModule",
                                RuntimeException::CONFIGURATION_ERROR);
    }

    if(nullptr == inputGenerator)
    {
        throw RuntimeException("IterativeController requires an InputGeneratorModule",
                                RuntimeException::CONFIGURATION_ERROR);
    }

    //Initialization and output modules are optional

}

/**
 * @brief Construct a new Iterative Controller object
 * 
 * @param name the name o the module
 */
IterativeController::IterativeController(
    std::string name) :
    ControllerModule(name),
    initializations(),
    stopSignalReceived(false)
{

}

IterativeController::~IterativeController()
{

}

void IterativeController::registerStorageNeeds(StorageRegistry& registry)
{
    ControllerModule::registerStorageNeeds(registry);
}

void IterativeController::registerMetadataNeeds(StorageRegistry& registry)
{
    totalNumTestCasesMetadataKey = registry.registerKey("TOTAL_TEST_CASES", StorageRegistry::INT, StorageRegistry::WRITE_ONLY);
}

bool IterativeController::run(StorageModule& storage, bool firstPass)
{
    bool done = false;
    time_t now;
    if(firstPass)
    {
        LOG_INFO << "Performing setup and calibration.";
        setup(storage);

        calibrate(storage);
        startTime = time(0);

        LOG_INFO << "Starting Fuzzing.";
        if(runTimeMinutes > 0)
        {
            LOG_INFO << "Controller configured to run for " << runTimeMinutes << " minutes.";
        }
        else
        {
            LOG_INFO << "Controller configured to run until stopped manually.";
        }
    }

    executeTestCases(firstPass, storage);

    analyzeResults(firstPass, storage);

    done = generateNewTestCases(firstPass, storage); //also clears the new list
    if(done)
    {
        LOG_INFO << "Fuzzing complete -- our own input generator indicated completion";
    }
    
    now = time(0);

    //If runTimeMinutes==0, then no runtime has been configured and the controller
    //should keep executing until shutdown manually
    if(runTimeMinutes>0)
    {
        //Otherwise, check if it is time to stop
        double runTime = difftime(now, startTime) / 60; //time in minutes
        
        if(runTime >= runTimeMinutes)
        {
            LOG_INFO << "Fuzzing complete -- run time of " << runTime << " minutes.";
            done = true;
        }
    }

    return done;
}

/**
 * @brief Helper method to run each of the initilization modules
 * Each module will be called once.  Subclasses may override this method to provide
 * different behavior.
 * @param storage the storage module
 */
void IterativeController::setup(StorageModule& storage)
{
    for(InitializationModule* m: initializations)
    {
        m->run(storage);
    }
}

/**
 * @brief Helper method to to call upon the input generator
 * This method will call both methods of the input generator, calling
 * upon storage to clearNewAndLocalEntries in between.  Subclasses may override 
 * this method to provide different behavior, but calling clearNewAndLocalEntries
 * is required at some point in the fuzzing loop.
 * 
 * @param firstPass true if this is the first call through the fuzzing loop
 * @param storage the storage module
 * @returns true if fuzzing should complete, false otherwise
 */
bool IterativeController::generateNewTestCases(bool firstPass, StorageModule& storage)
{
    bool done = false;
    //Only examine the test case results if this is not the first pass,
    //otherwise we will be examining results that came from the seed generators
    if(!firstPass)
    {
        //If the input generator says it is done, then we will consider fuzzing to be done as well
        //As we have no other input generation strategies in this controller
        done = inputGenerator->examineTestCaseResults(storage);
    }


    //Now clear the new list prior to generating more test cases
    //This will also delete any discarded new entries
    storage.clearNewAndLocalEntries();

    if(!done)
    {
        inputGenerator->addNewTestCases(storage);
    }

    return done;

}

/**
 * @brief Calls upon the executor module to calibrate
 * Each of the initial test cases in storage will be passed to the executor
 * for callibration.  
 * Subclasses may override this method to provide different behavior.
 * 
 * @param storage 
 */
void IterativeController::calibrate(StorageModule& storage)
{
    //Provide each test case in the initial corpus to the executor for calibration
    
    //Run each test case
    std::unique_ptr<Iterator> storageIterator = storage.getNewEntries();
    if(storageIterator->getSize()>0)
    {
        executor->runCalibrationCases(storage, storageIterator);
    }
    else
    {
        LOG_ERROR << "There are no seed test cases in storage to callibrate the executor with.";
    }
}


/**
 * @brief Helper method to execute all the new test cases
 * The executor will be called to run each one, and the feedback module will
 * be called to evaluate the results.
 * 
 * 
 * Subclasses may override this method to provide different behavior.
 * 
 * @param firstPass true if this is the first pass through the fuzzing loop
 * @param storage the storage module
 */
void IterativeController::executeTestCases(bool firstPass, StorageModule& storage)
{
    std::unique_ptr<Iterator> storageIterator = storage.getNewEntries();
    newCasesCount = storageIterator->getSize();

    executor->runTestCases(storage, storageIterator);
    storageIterator->resetIndex();
    feedback->evaluateTestCaseResults(storage, storageIterator);

    //Update TOTAL_TEST_CASES metadata
    StorageEntry& metadata = storage.getMetadata();
    int totalCasesCount =  metadata.getIntValue(totalNumTestCasesMetadataKey) + newCasesCount;
    metadata.setValue(totalNumTestCasesMetadataKey, totalCasesCount);
    
}

/**
 * @brief Helper method to call each of the output modules
 * Each module will be given a chance to run, using the OutputScheduler
 * for appropriately scheduling output modules.
 * Subclasses may override this method to provide different behavior.
 * 
 * @param firstPass 
 * @param storage 
 */
void IterativeController::analyzeResults(bool firstPass, StorageModule& storage)
{
    //The output scheduler handles determining which output modules are ready to run
    outScheduler.runOutputModules(newCasesCount, storage);
}
