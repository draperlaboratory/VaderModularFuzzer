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
#pragma once

#include "ControllerModulePattern.hpp"

namespace vmf
{


// Number of runs of the executor to disable an InputGenerator for if it fails to run
#define CYCLES_DISABLED 10

/**
 * @brief Data structure for holding statistics about each InputGenerator module.
 */
typedef struct InputGeneratorStats
{
    ///Number of times this InputGenerator was invoked
    unsigned int timesInvoked;
    ///How much time we've spent on this InputGenerator
    uint64_t timeSpent;
    ///How many testcases have been generated from this InputGenerator
    unsigned int testCasesGenerated;
    ///How many interesting/unique testcases have been found by this InputGenerator
    unsigned int newFindings;
    ///How many cycles of the Controller is this InputGenerator disabled for
    unsigned int cyclesDisabled;
} InputGeneratorStats;

/**
 * @brief The BalancedController can be configured with any number of InputGenerator modules.
 * It runs each of them and balances use of those InputGenerator modules by one of several metrics. It can do by total number of invocations (i.e., round-robin), by total time spent, or by total testcases generated.
 * 
 */
class BalancedController : public ControllerModulePattern {
public:

    static Module* build(std::string name);
    virtual void init(ConfigInterface& config);
    virtual bool run(StorageModule& storage, bool isFirstPass);

    BalancedController(std::string name);
    virtual ~BalancedController();

protected:

    virtual void executeTestCases(bool firstPass, StorageModule& storage);
    void printStats();
    void selectNextInputGenerator();
    std::string formatTime(uint64_t time);

    ///The set of input generators that we will balance invoking
    std::vector<InputGeneratorModule*> inputGenerators;
    ///Vector of stats, one for each InputGenerator (global for whole run)
    std::vector<InputGeneratorStats> inputGeneratorStats;
    ///Vector of stats, one for each InputGenerator (just for this epoch, reset every N minutes)
    std::vector<InputGeneratorStats> inputGeneratorStatsEpoch;
    ///The number of InputGenerator modules that we got configured with
    int numInputGen;
    ///The index of the InputGenerator module that was picked for this cycle of the controller
    int inputGenToUse;
    ///How much time has been spent in the current epoch
    uint64_t timeInEpoch = 0;
    ///How many minutes per epoch
    uint64_t epochLengthInMinutes = 0;

    // Configuration of balance metric
    ///Are we configured to balance by uses?
    bool balanceByUses;
    ///Are we configured to balance by time spent?
    bool balanceByTime;
    ///Are we configured to balance by number of testcases generated?
    bool balanceByTestcasesGenerated;
};
}
