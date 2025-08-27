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
#include "BalancedController.hpp"
#include "Logging.hpp"
#include "VmfUtil.hpp"
#include <cmath>

using namespace vmf;

#include "ModuleFactory.hpp"
REGISTER_MODULE(BalancedController);

/**
 * @brief Builder method to support the ModuleFactory
 * Constructs an instance of this class
 * @return Module* 
 */
Module* BalancedController::build(std::string name)
{
    return new BalancedController(name);
}

/**
 * @brief Initialization method
 * Reads in all configuration options for this class
 * 
 * @param config 
 */
void BalancedController::init(ConfigInterface& config)
{

    ControllerModulePattern::init(config);

    // Validate the configuration
    if (1 != executors.size())
    {
        throw RuntimeException("BalancedController requires a single ExecutorModule",
                                RuntimeException::CONFIGURATION_ERROR);
    }

    if (1 != feedbacks.size())
    {
        throw RuntimeException("BalancedController requires a single FeedbackModule",
                                RuntimeException::CONFIGURATION_ERROR);
    }

    inputGenerators = InputGeneratorModule::getInputGeneratorSubmodules(config, getModuleName());
    numInputGen = inputGenerators.size();

    if (numInputGen < 1)
    {
        throw RuntimeException("BalancedController requires at least one InputGenerator module",
                RuntimeException::CONFIGURATION_ERROR);
    }

    inputGenToUse = 0;

    // Create datastructures for holding statistics about each InputGenerator
    for (int i = 0; i < numInputGen; i++)
    {
        inputGeneratorStats.push_back(InputGeneratorStats());
        inputGeneratorStatsEpoch.push_back(InputGeneratorStats());
    }

    // Config options
    
    // Epoch length configuration
    epochLengthInMinutes = config.getIntParam(getModuleName(), "epochLengthInMinutes", 30);
    if (epochLengthInMinutes != 0)
    {
	LOG_INFO << "Configured to use epochs of length " << epochLengthInMinutes << " minutes.";
    }

    balanceByUses = false;
    balanceByTime = false;
    balanceByTestcasesGenerated = false;
    std::string balanceMetric = config.getStringParam(getModuleName(), "balanceMetric", "time");
    if (balanceMetric == "time")
    {
	balanceByTime = true;
    } else if (balanceMetric == "uses")
    {
	balanceByUses = true;
    } else if (balanceMetric == "testcasesGenerated")
    {
	balanceByTestcasesGenerated = true;
    } else {
        throw RuntimeException("BalancedController must be configured with a balanceMetric of either 'time', 'uses' or 'testcasesGenerated'.",
                               RuntimeException::CONFIGURATION_ERROR);
    }

    LOG_INFO << "BalancedController using balanceMetric: " << balanceMetric;
}

/**
 * @brief Construct a new BalancedController object
 * 
 * @param name the name of the module
 */
BalancedController::BalancedController(
    std::string name) :
    ControllerModulePattern(name)
{

}

BalancedController::~BalancedController()
{
    
}


bool BalancedController::run(StorageModule& storage, bool firstPass)
{

    uint64_t startTime = VmfUtil::getCurTime();    

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


	inputGenerators[inputGenToUse]->addNewTestCases(storage);

        inputGeneratorStats[inputGenToUse].timesInvoked++;
	inputGeneratorStatsEpoch[inputGenToUse].timesInvoked++;
    }

    // Run all the testcases we just generated (or got from the initial seeds)
    executeTestCases(firstPass, storage);

    // Record stats about this input gen: time spent, findings, testcases generated
    if (!firstPass)
    {
        // Time spent
        uint64_t timeSpent = VmfUtil::getCurTime() - startTime;
	timeInEpoch += timeSpent;

	// Add to global stats
        inputGeneratorStats[inputGenToUse].timeSpent += timeSpent;
        inputGeneratorStats[inputGenToUse].testCasesGenerated += storage.getNewEntries()->getSize();
        inputGeneratorStats[inputGenToUse].newFindings += storage.getNewEntriesThatWillBeSaved()->getSize();

	// Add to epoch stats
        inputGeneratorStatsEpoch[inputGenToUse].timeSpent += timeSpent;
        inputGeneratorStatsEpoch[inputGenToUse].testCasesGenerated += storage.getNewEntries()->getSize();
        inputGeneratorStatsEpoch[inputGenToUse].newFindings += storage.getNewEntriesThatWillBeSaved()->getSize();

         // If an input gen fails to make any testcases, take it out of circulation for a while
        if (storage.getNewEntries()->getSize() == 0)
        {
            inputGeneratorStatsEpoch[inputGenToUse].cyclesDisabled = CYCLES_DISABLED;
        }
    }

    // Run output modules etc
    analyzeResults(firstPass, storage);

    // Run examineTestCaseResults on all InputGenerators
    for (InputGeneratorModule * ig : inputGenerators)
    {
        ig -> examineTestCaseResults(storage);
    }

    // Clear out epoch if we are using epochs and enough time has passed
    if (epochLengthInMinutes != 0)
    {
	uint64_t minutesInEpoch = timeInEpoch / (1000 * 1000 * 60);
	if (minutesInEpoch > epochLengthInMinutes)
	{
	    LOG_INFO << "Reached end of epoch, clearing stats.";
	    timeInEpoch = 0;
	    for (int i = 0; i < numInputGen; i++)
	    {
		inputGeneratorStatsEpoch[i].timesInvoked = 0;
		inputGeneratorStatsEpoch[i].timeSpent = 0;
		inputGeneratorStatsEpoch[i].testCasesGenerated = 0;
		inputGeneratorStatsEpoch[i].newFindings = 0;
		inputGeneratorStatsEpoch[i].cyclesDisabled = 0;
	    }
	}
    }

    // Pick the next input generator for the next cycle
    selectNextInputGenerator();

    printStats();

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
void BalancedController::executeTestCases(bool firstPass, StorageModule& storage)
{
    ControllerModulePattern::executeTestCases(firstPass, storage);
}

/**
 * @brief Choose which input generator to use next.
 */
void BalancedController::selectNextInputGenerator()
{
    // Balance by number of invocations
    inputGenToUse = 0;

    // If balancing by total uses, pick the input gen with the fewest uses
    if (balanceByUses)
    {
        unsigned int fewestUses = inputGeneratorStatsEpoch[0].timesInvoked;
        for (int i = 1; i < numInputGen; i++)
        {
            unsigned int thisUses = inputGeneratorStatsEpoch[i].timesInvoked;
            if (thisUses < fewestUses && inputGeneratorStatsEpoch[i].cyclesDisabled == 0)
            {
                inputGenToUse = i;
                fewestUses = thisUses;
            }
        }
    }

    // If balancing by time, pick the input gen with the least time spent
    if (balanceByTime)
    {
        uint64_t shortestTime = inputGeneratorStatsEpoch[0].timeSpent;
        
        for (int i = 1; i < numInputGen; i++)
        {
            uint64_t thisTimeSpent = inputGeneratorStatsEpoch[i].timeSpent;
            if (thisTimeSpent < shortestTime && inputGeneratorStatsEpoch[i].cyclesDisabled == 0)
            {
                inputGenToUse = i;
                shortestTime = thisTimeSpent;
            }
        }
    }

    // If balancing by testcases generated, pick the input gen with the fewest testcases generated
    if (balanceByTestcasesGenerated)
    {
        unsigned int fewestGenerated = inputGeneratorStatsEpoch[0].testCasesGenerated;
        
        for (int i = 1; i < numInputGen; i++)
        {
            unsigned int thisGenerated  = inputGeneratorStatsEpoch[i].testCasesGenerated;
            if (thisGenerated < fewestGenerated && inputGeneratorStatsEpoch[i].cyclesDisabled == 0)
            {
                inputGenToUse = i;
                fewestGenerated = thisGenerated;
            }
        }
    }    
    
    // Reduce cycles disabled
    for (int i = 0; i < numInputGen; i++)
    {
        if (inputGeneratorStatsEpoch[i].cyclesDisabled > 0)
            inputGeneratorStatsEpoch[i].cyclesDisabled--;
    }
}

/**
 * @brief Print the statistics (uses, time spent, finding, # generated) for all
 * InputGenerators.
 */
void BalancedController::printStats()
{

    // Only run once every 5 seconds
    static uint64_t lastPrint = 0;
    uint64_t curTime = VmfUtil::getCurTime();
    uint64_t timeSincePrint = curTime - lastPrint;
    if (timeSincePrint < 5 * 1000 * 1000)
        return;

    // Print out table of stats

    // Header
    char formattedTitle[128];
    snprintf(formattedTitle, sizeof(formattedTitle), "%-26s%-9s%-14s%-10s%-20s", "InputGenerator", "Uses", "Time Spent", "Findings", "# Generated");
    LOG_INFO << formattedTitle;

    // One row of data per input gen
    for (int i = 0; i < numInputGen; i++)
    {
        char formattedRow[128];
        snprintf(formattedRow, sizeof(formattedRow),
                 "%-26s%-9d%-14s%-10d%-20d",
                 inputGenerators[i] -> getModuleName().c_str(),
                 inputGeneratorStats[i].timesInvoked,
                 formatTime(inputGeneratorStats[i].timeSpent).c_str(),
                 inputGeneratorStats[i].newFindings,
                 inputGeneratorStats[i].testCasesGenerated);
        LOG_INFO << formattedRow;
    }
    lastPrint = curTime;
    LOG_INFO << "---------------------------------";
    
}

/**
 * @brief Convert milliseconds to human readable time
 */
std::string BalancedController::formatTime(uint64_t time)
{
    // VmfUtil::getCurTime() reports milliseconds: convert to seconds
    double seconds = (double) time / (1000 * 1000);

    // Then round to 2 decimal places and convert to nearest human readable time unit
    double returnValue;
    std::string unit;
    if (seconds < 60)
    {
        returnValue = seconds;
        unit = "seconds";
    } else if (seconds < (60 * 60))
    {
        returnValue = seconds / 60;
        unit = "minutes";
    } else if (seconds < (60 * 60 * 24))
    {
        returnValue = seconds / (60 * 60);
        unit = "hours";
    } else
    {
        returnValue = seconds / (60 * 60 * 24);
        unit = "days";
    }

    std::ostringstream formattedTime;
    formattedTime << std::fixed << std::setprecision(2) << returnValue << " " << unit;
    return formattedTime.str();
}
