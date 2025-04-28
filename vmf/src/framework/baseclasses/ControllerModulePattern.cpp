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
#include "ControllerModulePattern.hpp"
#include "Logging.hpp"
#include "CDMSCommandAndCorpusHandler.hpp"

using namespace vmf;

/**
 * @brief Initialization method
 * Reads in all configuration options for this class
 * 
 * @param config 
 */
void ControllerModulePattern::init(ConfigInterface& config)
{
    runTimeMinutes = config.getIntParam(getModuleName(),"runTimeInMinutes", 0);
    keepAllSeeds = config.getBoolParam(getModuleName(),"keepAllSeeds", true);
    if(keepAllSeeds)
    {
        LOG_INFO << "Controller configured to keep all seeds";
    }
    else
    {
        LOG_INFO << "Controller configured to only keep seeds that are interesting";
    }

    //All the specified submodules are read in.  It is up to the subclass to determine
    //if this number of modules is supported by the controller.
    executors = ExecutorModule::getExecutorSubmodules(config, getModuleName());
    feedbacks = FeedbackModule::getFeedbackSubmodules(config, getModuleName());
    inputGenerators = InputGeneratorModule::getInputGeneratorSubmodules(config, getModuleName());
    outScheduler.setOutputModules(OutputModule::getOutputSubmodules(config, getModuleName()));
    initializations = InitializationModule::getInitializationSubmodules(config, getModuleName());

    //Initialize the command handler for distributed fuzzing (which loads additional config parameters)
    CDMSCommandAndCorpusHandler::getInstance().init(config,getModuleName());
}

/**
 * @brief Construct a new Iterative Controller object
 * 
 * @param name the name o the module
 */
ControllerModulePattern::ControllerModulePattern(
    std::string name) :
    ControllerModule(name),
    initializations(),
    stopSignalReceived(false)
{

}

ControllerModulePattern::~ControllerModulePattern()
{
    //Clear any in-progress loading of test cases for distributed fuzzing
    CDMSCommandAndCorpusHandler::getInstance().clearAnyInProgessLoading();
}

void ControllerModulePattern::registerStorageNeeds(StorageRegistry& registry)
{
    //The command handler has it's own data needs (for distributed fuzzing)
    CDMSCommandAndCorpusHandler::getInstance().registerStorageNeeds(registry);
}


void ControllerModulePattern::handleCommand(StorageModule& storage, bool isDistributed, ControllerModule::ControllerCmdType cmd)
{
    //Command handling is passed through to the helper class
    CDMSCommandAndCorpusHandler::getInstance().handleCommand(storage,isDistributed,cmd);
}

/**
 * @brief Helper method to call setup and calibration, with appropriate logging
 * Subclasses may wish to use this in their run methods on the first pass through the
 * fuzzing loop.  Note that the startTime variable is initialized in this method as well,
 * so subclasses that don't use this method will need to separately initialize the startTime
 * variable.
 * @param storage 
 */
void ControllerModulePattern::performInitialSetupAndCalibration(StorageModule& storage)
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

/**
 * @brief Helper method to determine if the configured execution time has passed
 * 
 * @return true if the time has passed
 * @return false if it has not, or if there is no configured execution time
 */
bool ControllerModulePattern::hasExecutionTimeCompleted()
{
    bool done = false;
    time_t now = time(0);

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
 * @brief Helper method to run each of the initialization modules
 * Each module will be called once.  Subclasses may override this method to provide
 * different behavior.
 * @param storage the storage module
 */
void ControllerModulePattern::setup(StorageModule& storage)
{
    for(InitializationModule* m: initializations)
    {
        m->run(storage);
    }

    // If configured to keep all seeds, then mark them all for saving now.
    // Otherwise we will only keep seeds with new coverage.
    if (keepAllSeeds)
    {
        std::unique_ptr<Iterator> entries = storage.getNewEntries();
        while (entries->hasNext())
        {
            StorageEntry * entry = entries -> getNext();
            storage.saveEntry(entry);
        }
    }
}

/**
 * @brief Helper method to to call upon the input generators
 * This implementations calls each of the input generators on every execution pass.
 * This method will call both methods of the input generator, calling
 * upon storage to clearNewAndLocalEntries in between.  Subclasses may override 
 * this method to provide different behavior, but calling clearNewAndLocalEntries
 * is required at some point in the fuzzing loop.
 * 
 * Note: This implementation will stop fuzzing if any of the input generators
 * indicate that they are done.  Subclasses may want to override this behavior
 * to provide a different behavior.
 * 
 * @param firstPass true if this is the first call through the fuzzing loop
 * @param storage the storage module
 * @returns true if fuzzing should complete, false otherwise
 */
bool ControllerModulePattern::generateNewTestCases(bool firstPass, StorageModule& storage)
{
    bool done = false;

    //Only examine the test case results if this is not the first pass,
    //otherwise we will be examining results that came from the seed generators
    if(!firstPass)
    {
        //If any input generator says it is done, then we will consider fuzzing to be done as well
        for(InputGeneratorModule* inputGenerator : inputGenerators)
        {
            done = done || inputGenerator->examineTestCaseResults(storage);
        }

    }


    //Now clear the new list prior to generating more test cases
    //This will also delete any discarded new entries
    storage.clearNewAndLocalEntries();

    if(!done)
    {
        for(InputGeneratorModule* inputGenerator: inputGenerators)
        {
            inputGenerator->addNewTestCases(storage);
        }
    }

    return done;
}

/**
 * @brief Calls upon the executor modules to calibrate
 * Each of the initial test cases in storage will be passed to each of the executors
 * for calibration.  
 * Subclasses may override this method to provide different behavior.
 * 
 * @param storage 
 */
void ControllerModulePattern::calibrate(StorageModule& storage)
{
    //Provide each test case in the initial corpus to the executor for calibration
    
    //Run each test case
    std::unique_ptr<Iterator> storageIterator = storage.getNewEntries();
    if(storageIterator->getSize()>0)
    {
        for(ExecutorModule* executor: executors)
        {
            executor->runCalibrationCases(storage, storageIterator);
            storageIterator->resetIndex();
        }
    }
    else
    {
        LOG_ERROR << "There are no seed test cases in storage to calibrate the executor with.";
    }
}


/**
 * @brief Helper method to execute all the new test cases
 * Each executor will be called to run each one, and each feedback module will
 * be called to evaluate the results.
 * 
 * Subclasses may override this method to provide different behavior.
 * 
 * @param firstPass true if this is the first pass through the fuzzing loop
 * @param storage the storage module
 */
void ControllerModulePattern::executeTestCases(bool firstPass, StorageModule& storage)
{
    std::unique_ptr<Iterator> storageIterator = storage.getNewEntries();

    for(ExecutorModule* executor: executors)
    {
        executor->runTestCases(storage, storageIterator);
        storageIterator->resetIndex();
    }

    for(FeedbackModule* feedback: feedbacks)
    {
        feedback->evaluateTestCaseResults(storage, storageIterator);
        storageIterator->resetIndex();
    }
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
void ControllerModulePattern::analyzeResults(bool firstPass, StorageModule& storage)
{
    //The output scheduler handles determining which output modules are ready to run
    outScheduler.runOutputModules(newCasesCount, storage);
}
