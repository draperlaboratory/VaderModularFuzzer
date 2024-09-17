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
    ControllerModulePattern::init(config);
    
    if(1 != executors.size())
    {
        throw RuntimeException("IterativeController requires a single ExecutorModule",
                                RuntimeException::CONFIGURATION_ERROR);
    }

    if(1 != feedbacks.size())
    {
        throw RuntimeException("IterativeController requires a single FeedbackModule",
                                RuntimeException::CONFIGURATION_ERROR);
    }

    if(1 != inputGenerators.size())
    {
        throw RuntimeException("IterativeController requires a single InputGeneratorModule",
                                RuntimeException::CONFIGURATION_ERROR);
    }

    //Initialization and output modules are optional, and any number are supported
}

/**
 * @brief Construct a new Iterative Controller object
 * 
 * @param name the name o the module
 */
IterativeController::IterativeController(
    std::string name) :
    ControllerModulePattern(name)
{

}

IterativeController::~IterativeController()
{

}


bool IterativeController::run(StorageModule& storage, bool firstPass)
{
    bool done = false;
    if(firstPass)
    {
        performInitialSetupAndCalibration(storage);
    }

    executeTestCases(firstPass, storage);

    analyzeResults(firstPass, storage);

    done = generateNewTestCases(firstPass, storage); //also clears the new list
    if(done)
    {
        LOG_INFO << "Fuzzing complete -- our own input generator indicated completion";
    }

    done = hasExecutionTimeCompleted();

    return done;
}
