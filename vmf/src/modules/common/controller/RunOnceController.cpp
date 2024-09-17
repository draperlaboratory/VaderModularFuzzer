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
#include "RunOnceController.hpp"
#include "Logging.hpp"

using namespace vmf;

#include "ModuleFactory.hpp"
REGISTER_MODULE(RunOnceController);

/**
 * @brief Builder method to support the ModuleFactory
 * Constructs an instance of this class
 * @return Module* 
 */
Module* RunOnceController::build(std::string name)
{
    return new RunOnceController(name);
}

/**
 * @brief Initialization method
 * Reads in all configuration options for this class
 * 
 * @param config 
 */
void RunOnceController::init(ConfigInterface& config)
{
    ControllerModulePattern::init(config);

    //Read in the output modules ourself, because we don't want to use the OutputScheduler for this controller
    outputs = OutputModule::getOutputSubmodules(config, getModuleName());

    if((0 != feedbacks.size()))
    {
        //A least one executor must be specified to use a feedback module
        if(0 ==executors.size())
        {
            throw RuntimeException("FeedbackModules cannot be specified without at least one ExecutorModule",
                                   RuntimeException::CONFIGURATION_ERROR);
        }
    }

    //If there is an executor module, then a feedback module must be provided
    if((0 != executors.size()) && (0 == feedbacks.size()))
    {
            throw RuntimeException("ExecutorModules cannot be specified without at least one FeedbackModule",
                                   RuntimeException::CONFIGURATION_ERROR);
    }

}

/**
 * @brief Construct a new Iterative Controller object
 * 
 * @param name the name o the module
 */
RunOnceController::RunOnceController(
    std::string name) :
    ControllerModulePattern(name)
{

}

RunOnceController::~RunOnceController()
{

}


bool RunOnceController::run(StorageModule& storage, bool firstPass)
{
    //Run any initialization modules
    for(InitializationModule* m: initializations)
    {
        m->run(storage);
    }

    //Run any input generator modules
    for(InputGeneratorModule* m: inputGenerators)
    {
        m->addNewTestCases(storage);
    }

    //If there is any executors, callibrate them and run them
    if(0 != executors.size())
    {
        calibrate(storage);
        executeTestCases(firstPass, storage);
    }

    //Let the input generators evaluate any results
    for(InputGeneratorModule* m: inputGenerators)
    {
        //Ignore the results, as we don't care if the input generators are done, since they only run once anyway
        m->examineTestCaseResults(storage);
    }

    //Run any output modules
    for(OutputModule* m: outputs)
    {
        m->run(storage);
    }

    //Now clear the new list.
    //This will also delete any discarded new entries
    storage.clearNewAndLocalEntries();

    return true; //execution always finishes after one fuzzing loop run
}



