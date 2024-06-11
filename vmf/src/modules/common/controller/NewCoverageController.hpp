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
#pragma once

// include common modules
#include "ControllerModule.hpp"
#include "ExecutorModule.hpp"
#include "FeedbackModule.hpp"
#include "InputGeneratorModule.hpp"
#include "InitializationModule.hpp"
#include "OutputModule.hpp"
#include "OutputScheduler.hpp"
#include "StorageModule.hpp"
#include "RuntimeException.hpp"

#include <vector>

namespace vmf
{
/**
 * @brief Controller that supports multiple InputGenerator modules
 * The NewCoverageController is similar to the IterativeController, except
 * that it supports two InputGenerator modules.  This controller will temporarily
 * toggle to an alternative input generator every time there is are new, interesting
 *  test cases saved in storage (typically this occurs due to new coverage, though 
 * the exact decision is made in the feedback module).  The examineTestCaseResults()
 * method is called on both input generators during each pass through the fuzzing loop, 
 * but the addNewTestCases() method is called on only the active input generator.
 * 
 */
class NewCoverageController : public ControllerModule {
public:

    static Module* build(std::string name);
    virtual void init(ConfigInterface& config);
    virtual void registerStorageNeeds(StorageRegistry& registry);
    virtual void registerMetadataNeeds(StorageRegistry& registry);
    virtual bool run(StorageModule& storage, bool isFirstPass);

    NewCoverageController(std::string name);
    virtual ~NewCoverageController();

protected:

    virtual void setup(StorageModule& storage);
    virtual void calibrate(StorageModule& storage);
    virtual void executeTestCases(StorageModule& storage);
    virtual void analyzeResults(StorageModule& storage);
    void selectNextInputGenerator();

    /// Only one executor module is allowed
    ExecutorModule* executor;
 
    /// Only one feeback module is allowed
    FeedbackModule* feedback;

    /// The main input generator (which will run until new coverage is encountered)
    InputGeneratorModule* primaryInputGen;
    /// The secondary input generator (which will run when the first input generator finds new coverage)
    InputGeneratorModule* newCoverageInputGen;

    /// Currently active InputGenerator:
    InputGeneratorModule* currentInputGen;

    /// Multiple initialization modules are allowed
    std::vector<InitializationModule*> initializations;

    /// Multiple output modules are allowed, and are all handled within OutputScheduler
    OutputScheduler outScheduler;

    /// The handle to the TOTAL_TEST_CASES metadata field
    int totalNumTestCasesMetadataKey;

    /// This will be true when the controller has been signaled to stop
    bool stopSignalReceived;

    /// State tracking for NewCoverageController, was there new coverage
    bool foundNewCoverageThisCycle = false;
    /// State tracking for NewCoverageController, does the input generator want to run again
    bool inputGenRunAgain = false;

    /// The is the maximum amount of time the controller should execute for
    int runTimeMinutes;
    
    /// This is the number of new test cases executed on this execution of the fuzzing loop
    int newCasesCount;
    
    /// This is the start time of the controller
    time_t startTime;
};
}
