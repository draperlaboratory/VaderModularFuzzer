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
#include "NewCoverageController.hpp"
#include "Logging.hpp"

using namespace vmf;

#include "ModuleFactory.hpp"
REGISTER_MODULE(NewCoverageController);

/**
 * @brief Builder method to support the ModuleFactory
 * Constructs an instance of this class
 * @return Module* 
 */
Module* NewCoverageController::build(std::string name)
{
    return new NewCoverageController(name);
}

/**
 * @brief Initialization method
 * Reads in all configuration options for this class
 * 
 * @param config 
 */
void NewCoverageController::init(ConfigInterface& config)
{

    ControllerModule::init(config);
    runTimeMinutes = config.getIntParam(getModuleName(),"runTimeInMinutes", 0);

    executor = nullptr;
    feedback = nullptr;

    // We require exactly 1 executor and 1 feedback module
    executor = ExecutorModule::getExecutorSubmodule(config, getModuleName());
    feedback = FeedbackModule::getFeedbackSubmodule(config, getModuleName());

    // Initialization and input generators we can support multiple
    std::vector<InputGeneratorModule*> inputGenerators;
    inputGenerators = InputGeneratorModule::getInputGeneratorSubmodules(config, getModuleName());    
    outScheduler.setOutputModules(OutputModule::getOutputSubmodules(config, getModuleName()));
    initializations = InitializationModule::getInitializationSubmodules(config, getModuleName());

    // Validate the configuration
    if (nullptr == executor)
    {
        throw RuntimeException("NewCoverageController requires an ExecutorModule",
                                RuntimeException::CONFIGURATION_ERROR);
    }

    if (nullptr == feedback)
    {
        throw RuntimeException("NewCoverageController requires a FeedbackModule",
                                RuntimeException::CONFIGURATION_ERROR);
    }

    // User provides name of the two input generators
    std::string primaryInputGenName = config.getStringParam(getModuleName(),"primaryInputGenerator");
    std::string newCoverageInputGenName = config.getStringParam(getModuleName(),"newCoverageInputGenerator");

    // Then we fetch them by name
    primaryInputGen = InputGeneratorModule::getInputGeneratorSubmoduleByName(config, getModuleName(), primaryInputGenName);
    newCoverageInputGen = InputGeneratorModule::getInputGeneratorSubmoduleByName(config, getModuleName(), newCoverageInputGenName);

    if (primaryInputGen == nullptr)
    {
	throw RuntimeException("NewCoverageController requires primaryInputGenerator",
			RuntimeException::CONFIGURATION_ERROR);
    }

    if (newCoverageInputGen == nullptr)
    {
	throw RuntimeException("NewCoverageController requires newCoverageInputGenerator",
			RuntimeException::CONFIGURATION_ERROR);
    }

    // We start off using the primaryInputGen
    currentInputGen = primaryInputGen;
}

/**
 * @brief Construct a new Iterative Controller object
 * 
 * @param name the name o the module
 */
NewCoverageController::NewCoverageController(
    std::string name) :
    ControllerModule(name),
    initializations(),
    stopSignalReceived(false)
{

}

NewCoverageController::~NewCoverageController()
{
    
}

void NewCoverageController::registerStorageNeeds(StorageRegistry& registry)
{
    ControllerModule::registerStorageNeeds(registry);
}

void NewCoverageController::registerMetadataNeeds(StorageRegistry& registry)
{
    totalNumTestCasesMetadataKey = registry.registerKey("TOTAL_TEST_CASES", StorageRegistry::INT, StorageRegistry::WRITE_ONLY);
}

bool NewCoverageController::run(StorageModule& storage, bool firstPass)
{
    bool done = false;
    time_t now;
    if (firstPass)
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

    // Call the current input generator to make new test cases.
    // Skip generating on the first pass because we use initial seeds instead.
    if (!firstPass)
    {
	// Clear out tags
	storage.clearNewAndLocalEntries();

	//generateNewTestCases(storage);
	currentInputGen->addNewTestCases(storage);
    }

    // Run all the testcases we just generated (or got from the initial seeds)
    executeTestCases(storage);

    // Run output modules etc
    analyzeResults(storage);

    // We call examineTestCaseResults on all InputGenerators
    bool primaryRunAgain = primaryInputGen -> examineTestCaseResults(storage);
    bool newCovRunAgain = newCoverageInputGen -> examineTestCaseResults(storage);

    // Use the result of the current inputgen
    if (currentInputGen == primaryInputGen)
        inputGenRunAgain = primaryRunAgain;
    else
        inputGenRunAgain = newCovRunAgain;

    // Pick the next input generator for the next cycle
    selectNextInputGenerator();

    // Detect exiting early if configured to only run for N minutes.
    // runTimeMinutes == 0 means no limit.
    now = time(0);
    if (runTimeMinutes>0)
    {
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
void NewCoverageController::setup(StorageModule& storage)
{
    for (InitializationModule* m: initializations)
    {
        m->run(storage);
    }
}

/**
 * @brief Calls upon the executor module to calibrate
 * Each of the initial test cases in storage will be passed to the executor
 * for callibration.  
 * Subclasses may override this method to provide different behavior.
 * 
 * @param storage 
 */
void NewCoverageController::calibrate(StorageModule& storage)
{
    //Provide each test case in the initial corpus to the executor for calibration
    
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
 * @brief Helper method to execute all the new test cases.
 * @param storage the storage module
 */
void NewCoverageController::executeTestCases(StorageModule& storage)
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

    // Look up how many of this batch will be saved.
    // If more than zero, we switch to the newCoverageInputGen.
    storageIterator = storage.getNewEntriesThatWillBeSaved();
    foundNewCoverageThisCycle = storageIterator->getSize() > 0;
}

/**
 * @brief Choose which input generator to use next.
 * Currently, we use whether or not there was new coverage and
 * if the last input generator was done to decide which to pick next.
 */
void NewCoverageController::selectNextInputGenerator()
{

    // If the last input generator indicated it wants to run again,
    // then don't change the input generator.
    if (inputGenRunAgain)
    {
	// LOG_INFO << "Keeping current input generator: " << currentInputGen -> getModuleName();
	return;
    }

    // Otherwise, if there was new coverage use the new coverage input gen.
    if (foundNewCoverageThisCycle)
    {
	//LOG_INFO << "New coverage, switching to newCovInputGen";
	currentInputGen = newCoverageInputGen;
	return;
    }

    // If no new coverage and no input generator wanted to run again, then
    // default to primary.
    // LOG_INFO << "Defaulting back to primary input gen";
    currentInputGen = primaryInputGen;
}

/**
 * @brief Helper method to call each of the output modules
 * Each module will be given a chance to run, using the OutputScheduler
 * for appropriately scheduling output modules.
 * Subclasses may override this method to provide different behavior.
 * 
 * @param storage
 */
void NewCoverageController::analyzeResults(StorageModule& storage)
{
    //The output scheduler handles determining which output modules are ready to run
    outScheduler.runOutputModules(newCasesCount, storage);
}
