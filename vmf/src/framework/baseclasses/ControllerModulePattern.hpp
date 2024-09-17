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
 * @brief Helper class for implementing controllers.
 * This class cannot be used as a controller on it's own, as it does not implement
 * the run method.  Rather, it provides helper methods that can be used as the basis 
 * of implementing a controller.  These run methods assume that at least one module of
 * each type has been providing in the ConfigInterface.
 * This controller supports any number of modules.  What modules are required and any
 * limitations on the number of supported modules should be determined in any subclasses.
 */
class ControllerModulePattern : public ControllerModule {
public:

    virtual void init(ConfigInterface& config);

    virtual void registerStorageNeeds(StorageRegistry& registry);

    virtual void handleCommand(StorageModule& storage, bool isDistributed, ControllerModule::ControllerCmdType cmd);

    ControllerModulePattern(std::string name);
    virtual ~ControllerModulePattern();

protected:
    //These methods are provided for subclasses that wish to alter the controller behavior
    virtual void setup(StorageModule& storage);
    virtual void calibrate(StorageModule& storage);
    virtual void performInitialSetupAndCalibration(StorageModule& storage);
    virtual bool generateNewTestCases(bool firstPass, StorageModule& storage);
    virtual void executeTestCases(bool firstPass, StorageModule& storage);
    virtual void analyzeResults(bool firstPass, StorageModule& storage);

    bool hasExecutionTimeCompleted();

    ///The executor submodules
    std::vector<ExecutorModule*> executors;
    ///The feedback submodules
    std::vector<FeedbackModule*> feedbacks; 
    ///The input generator submodules
    std::vector<InputGeneratorModule*> inputGenerators; 
    ///The initialization modules
    std::vector<InitializationModule*> initializations;
    ///The output modules, all managed within OutputScheduler
    OutputScheduler outScheduler;

    ///This will be true when the controller has been signaled to stop
    bool stopSignalReceived;
    ///The is the maximum amount of time the controller should execute for
    int runTimeMinutes;
    ///This is the number of new test cases executed on this execution of the fuzzing loop
    int newCasesCount;
    ///This is the start time of the controller
    time_t startTime;
    ///Whether or not we keep all initial seeds
    bool keepAllSeeds;
};
}
