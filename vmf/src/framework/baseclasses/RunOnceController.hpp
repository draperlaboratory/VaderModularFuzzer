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
#include "StorageModule.hpp"
#include "RuntimeException.hpp"

#include <vector>


namespace vader
{
/**
 * @brief Controller runs every provided module exactly once before shutting down
 * This Controller supports any number of initializationModules, inputGeneratorModules, and outputModules.
 * Up to one executor, feedback, and formatter module are supported.  All module types are optional, however
 * a feedback or formatter module cannot be specified without an executor to go with it, and if
 * an executor module is used a feedback modules must be provided as well.
 */
class RunOnceController : public ControllerModule {
public:

    static Module* build(std::string name);
    virtual void init(ConfigInterface& config);

    virtual void registerStorageNeeds(StorageRegistry& registry);
    virtual void registerMetadataNeeds(StorageRegistry& registry);

    virtual bool run(StorageModule& storage, bool isFirstPass);

    RunOnceController(std::string name);
    virtual ~RunOnceController();

protected:

    virtual void calibrate(StorageModule& storage);
    virtual void executeTestCases(bool firstPass, StorageModule& storage);

    ///The list of InitializationModules being used by this controller
    std::vector<InitializationModule*> initializations;
    
    ///The list of InputGeneratorModules being used by this controller
    std::vector<InputGeneratorModule*> inputGenerators; 
   
    ///The ExecutorModule being used by this controller
    ExecutorModule* executor;
   
    ///The FeedbackModule being used by this controller
    FeedbackModule* feedback; 
    
    ///The FormatterModule being used by this controller
    FormatterModule* formatter;

    ///The list of OutputModules being used by this controller
    std::vector<OutputModule*> outputs;

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

    ///This is the number of new test cases executed on this execution of the fuzzing loop
    int newCasesCount;

};
}