/* =============================================================================
 * Vader Modular Fuzzer (VMF)
 * Copyright (c) 2021-2023 The Charles Stark Draper Laboratory, Inc.
 * <vader@draper.com>
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
#include "FormatterModule.hpp"
#include "InputGeneratorModule.hpp"
#include "InitializationModule.hpp"
#include "OutputModule.hpp"
#include "OutputScheduler.hpp"
#include "StorageModule.hpp"
#include "RuntimeException.hpp"

#include <vector>


namespace vader
{
/**
 * @brief Controller that simply iterates through each module, calling them in sequence.
 * This controller supports one InputGenerator, one Executor, and any number of Initialization
 * and Output modules.
 */
class IterativeController : public ControllerModule {
public:

    static Module* build(std::string name);
    virtual void init(ConfigInterface& config);

    virtual void registerStorageNeeds(StorageRegistry& registry);
    virtual void registerMetadataNeeds(StorageRegistry& registry);

    virtual bool run(StorageModule& storage, bool isFirstPass);

    IterativeController(std::string name);
    virtual ~IterativeController();

protected:
    //These methods are provided for subclasses that wish to alter the controller behavior
    virtual void setup(StorageModule& storage);
    virtual void calibrate(StorageModule& storage);
    virtual void generateNewTestCases(bool firstPass, StorageModule& storage);
    virtual void executeTestCases(bool firstPass, StorageModule& storage);
    virtual void analyzeResults(bool firstPass, StorageModule& storage);

    ///Only one executor module is allowed
    ExecutorModule* executor;
    ///Only one feeback module is allowed
    FeedbackModule* feedback; 
     ///Only one formatter module is allowed
    FormatterModule* formatter;
    ///Only one input generator module is allowed
    InputGeneratorModule* inputGenerator; 
    ///Multiple initialization modules are allowed
    std::vector<InitializationModule*> initializations;
    ///Multiple output modules are allowed, and are all handled within OutputScheduler
    OutputScheduler outScheduler;

    ///The handle to the TEST_CASE_FORMATTED field
    int testCaseFormattedKey;
    ///The handle to the TOTAL_TEST_CASES metadata field
    int totalNumTestCasesMetadataKey;

    ///True if there is a registered formatter
    bool useFormatter;
    ///Working buffer for the formatter
    char* formatterBuffer;
    ///The maximum size for the formatterBuffer
    static const int FORMATTER_BUFF_SZ = (1024 * 1024);

    ///This will be true when the controller has been signaled to stop
    bool stopSignalReceived;
    ///The is the maximum amount of time the controller should execute for
    int runTimeMinutes;
    ///This is the number of new test cases executed on this execution of the fuzzing loop
    int newCasesCount;
    ///This is the start time of the controller
    time_t startTime;
};
}