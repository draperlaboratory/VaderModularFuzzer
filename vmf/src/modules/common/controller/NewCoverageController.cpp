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

    ControllerModulePattern::init(config);

    // Validate the configuration
    if (1 != executors.size())
    {
        throw RuntimeException("NewCoverageController requires a single ExecutorModule",
                                RuntimeException::CONFIGURATION_ERROR);
    }

    if (1 != feedbacks.size())
    {
        throw RuntimeException("NewCoverageController requires a single FeedbackModule",
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
 * @brief Construct a new New Coverage Controller object
 * 
 * @param name the name o the module
 */
NewCoverageController::NewCoverageController(
    std::string name) :
    ControllerModulePattern(name)
{

}

NewCoverageController::~NewCoverageController()
{
    
}


bool NewCoverageController::run(StorageModule& storage, bool firstPass)
{
    bool done = false;
    if (firstPass)
    {
        performInitialSetupAndCalibration(storage);
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
    executeTestCases(firstPass, storage);

    // Run output modules etc
    analyzeResults(firstPass, storage);

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

    done = hasExecutionTimeCompleted();

    return done;
}


/**
 * @brief Helper method to execute all the new test cases.
 * This version of the method determines whether or not new coverage
 * was found on this pass, and sets the foundNewCoverageThisCycle flag accordingly
 * @param firstPass whether or not this the first pass through execution
 * @param storage the storage module
 */
void NewCoverageController::executeTestCases(bool firstPass, StorageModule& storage)
{
    ControllerModulePattern::executeTestCases(firstPass, storage);

    // Look up how many of this batch will be saved.
    // If more than zero, we switch to the newCoverageInputGen.
    std::unique_ptr<Iterator> storageIterator = storage.getNewEntries();
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
        //LOG_DEBUG<< "Keeping current input generator: " << currentInputGen -> getModuleName();
        return;
    }

    // Otherwise, if there was new coverage use the new coverage input gen.
    if (foundNewCoverageThisCycle)
    {
        //LOG_DEBUG << "New coverage, switching to newCovInputGen";
        currentInputGen = newCoverageInputGen;
        return;
    }

    // If no new coverage and no input generator wanted to run again, then
    // default to primary.
    // LOG_DEBUG << "Defaulting back to primary input gen";
    currentInputGen = primaryInputGen;
}

