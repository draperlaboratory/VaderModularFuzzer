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
#include "OutputScheduler.hpp"
#include "RuntimeException.hpp"
#include "Logging.hpp"

using namespace vmf;

OutputScheduler::OutputScheduler()
{
    initialized = false;
    modulesSet = false;
}

OutputScheduler::~OutputScheduler()
{
    //Nothing needed
}

/**
* @brief Configure the OutputScheduler with the set of output modules to execute
* Controllers should call this method during initialization to provide the
* full list of output modules that should be scheduled.  Initialization may only
* be called once.
* @param outputs the output modules that should be executed
* @throws RuntimeException if the any module configuration is invalid or if initialization
* is called more than once.
*/
void OutputScheduler::setOutputModules(std::vector<OutputModule*> outputs)
{
    if(!modulesSet)
    {
        for(OutputModule* m: outputs)
        {
            OutputModuleData data;
            data.theModule = m;
            data.lastRanTime = time(0);

            moduleData.push_back(data);
        }
        modulesSet = true;
    }
    else
    {
        throw RuntimeException("Attempt to set modules in OutputScheduler more than once", 
            RuntimeException::USAGE_ERROR);
    }
}

/**
 * @brief Helper method to complete output scheduler initialization.  This occurs
 * the first time runOutputModules is called, because we want to delay calling the
 * module schedule rate methods until after all modules are fully initialized.  Otherwise,
 * depending on the initialization order, modules might not have had time to read their
 * configuration parameters first.
 */
void OutputScheduler::loadModuleScheduleRates()
{
    for(OutputModuleData& data: moduleData)
    {
        OutputModule* m = data.theModule;
        data.type = m->getDesiredScheduleType();
        data.rate = m->getDesiredScheduleRate();
        data.testCaseCounter = data.rate;

        //A schedule rate must be specified for CALL_ON_NUM_X scheduling types
        if((OutputModule::CALL_ON_NUM_SECONDS == data.type)||
            (OutputModule::CALL_ON_NUM_TEST_CASE_EXECUTIONS == data.type))
        {
            if(data.rate<=0)
            {
                LOG_ERROR << m->getModuleName() << " has invalid desired schedule parameters";
                throw RuntimeException("getDesiredScheduleRate must return non-zero value", 
                    RuntimeException::CONFIGURATION_ERROR);
            }
        }
    }
    initialized = true;
}

/**
* @brief Run the output modules
* This method will run each output module based on it's configured scheduling
* parameters.  For the most effective scheduling, controllers should call this
* method once per execution of the main fuzzing loop.
* 
* @param newTestCaseCount the number of new test cases that have been executed
* @param storage the storage module to provide to the output modules that should be run
* since the last call to runOutputModules()
*/
void OutputScheduler::runOutputModules(int newTestCaseCount, StorageModule& storage)
{

    if(!modulesSet)
    {
        throw RuntimeException("Attempt to run OutputScheduler without setting modules", 
            RuntimeException::USAGE_ERROR);
    }
    if(!initialized)
    {
        loadModuleScheduleRates();
    }

    //Now run the modules
    for(unsigned int i=0; i<moduleData.size(); i++)
    {
        OutputModuleData& data = moduleData[i];
        bool runModule = false;
        if(OutputModule::CALL_ON_NUM_SECONDS == data.type)
        {
            time_t now = time(0);
            double elapsed = difftime(now, data.lastRanTime);
            if(elapsed >= data.rate)
            {
                runModule = true;
                data.lastRanTime = now;
            }
        }
        else if (OutputModule::CALL_ON_NUM_TEST_CASE_EXECUTIONS == data.type)
        {
            data.testCaseCounter = data.testCaseCounter - newTestCaseCount;
            if(data.testCaseCounter <= 0)
            {
                runModule = true;
                data.testCaseCounter = data.rate;
            }
        }
        else if(OutputModule::CALL_EVERYTIME == data.type)
        {
            runModule = true;
        }
        //else type is CALL_ONLY_ON_SHUTDOWN, in which case the module's run method 
        //is never called

        if(runModule)
        {
            data.theModule->run(storage);
        }
    }

}