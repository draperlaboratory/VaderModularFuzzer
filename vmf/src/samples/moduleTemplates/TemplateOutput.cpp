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
#include "TemplateOutput.hpp"
#include "Logging.hpp"

using namespace vmf;

/*
  This will register the mutator module with the VMF module factory, making
  it available for use via VMF configuration files.
 */
#include "ModuleFactory.hpp"
REGISTER_MODULE(TemplateOutput);

/**
 * @brief Builder method to support the ModuleFactory
 * Constructs an instance of this class
 * @return Module* 
 */
Module* TemplateOutput::build(std::string name)
{
    return new TemplateOutput(name);
}

/**
 * @brief Initialization method
 * Reads in all configuration options for this class
 * 
 * @param config 
 */
void TemplateOutput::init(ConfigInterface& config)
{
    //Call upon the config option to read any config parameters, such as
    //config.getIntParam(getModuleName(), "parameterName");
}

/**
 * @brief Construct a new TemplateOutput::TemplateOutput object
 * 
 * @param name name of instance 
 */
TemplateOutput::TemplateOutput(std::string name) :
    OutputModule(name)
{
}

/**
 * @brief Destroy the TemplateOutput::TemplateOutput object
 */
TemplateOutput::~TemplateOutput()
{
}

/**
 * @brief Registers storage needs
 * 
 * @param registry 
 */
void TemplateOutput::registerStorageNeeds(StorageRegistry& registry)
{
    crashedTag = registry.registerTag("CRASHED", StorageRegistry::READ_ONLY);
}

/**
 * @brief Perform any ongoing output module functions that should occur during fuzzing
 *
 * Override getDesiredScheduleType and getDesiredScheduleRate to control how often and
 * when the run method is called.  By default, the run method will be called after every
 * new set of test cases is executed, but this will be too frequent for many output module
 * functions.
 *
 * @param storage
 */
void TemplateOutput::run(StorageModule& storage)
{
    //This simplistic module just checks for any new crashing test cases
    //and stores the resulting total count in metadata
    unsigned int numNewCrashes = storage.getNewEntriesByTag(crashedTag)->getSize();
    if(numNewCrashes > 0)
    {
        StorageEntry& metadata = storage.getMetadata();
        unsigned int newCount = metadata.getUIntValue(numCrashesHandle) + numNewCrashes;
        metadata.setValue(numCrashesHandle, newCount);
    }

}

/* ------------The methods below are optional for OutputModules -------------- */

/**
 * @brief Modules using global metadata must also register fields that they intend to read or write
 *
 * Not all modules use metadata (which is summary data collected across the entries stored in storage),
 * hence this is an optional method.
 *
 * @param registry
 */
void TemplateOutput::registerMetadataNeeds(StorageRegistry& registry)
{
    numCrashesHandle = registry.registerKey("NUM_CRASHES",StorageRegistry::UINT,StorageRegistry::READ_WRITE);
}

/** @brief Perform any shutdown output processing
 * 
 * Many output modules may wish to peform special processing when the controller is
 * shutdown (such as writing any final data to disk, or running one more time on
 * any outputs that haven't been processed yet).  This method is optional.
 * 
 * @param storage 
 */
/*void TemplateOutput::shutdown(StorageModule& storage)
{

}*/

/**
 * @brief Get the desired scheduling approach for this output module
 * The default implementation of this method returns CALL_EVERYTIME.
 * 
 * To run less often, override this method to return an alternate schedule type.  
 * All scheduling methods are approximate, as output modules are called a quiescent 
 * time in the fuzzing loop, which may not align exactly with the desired scheduling rate.
 * 
 * CALL_EVERYTIME: The module will run on every pass through the main fuzzing loop.  
 * 
 * CALL_ON_NUM_SECONDS: The module will be called at a period of at least getDesiredScheduleRate()
 * seconds from the prior call.  For eample, if getDesiredScheduleRate() returns 5, then the module
 * will be called approximately every 5s.
 * 
 * CALL_ON_NUM_TEST_CASE_EXECUTIONS: The module will be called when at least getDesiredScheduleRate()
 * more test cases have been executes since the prior call.  For example, if getDesiredScheduleRate()
 * returns 10000, then this module will be called when approximately another 10,000 test cases have 
 * executed.
 * 
 * CALL_ONLY_ON_SHUTDOWN: The module will not run as part of the main fuzzing loop, and will
 * instead only run on shutdown.  Make sure to override the shutdown() method with this scheduling
 * type, as only the shutdown() method is called at shutdown.  The run() method will never be
 * called with this scheduling type.
 * 
 * @return ScheduleTypeEnum the desired schedule type
 */
/*OutputModule::ScheduleTypeEnum TemplateOutput::getDesiredScheduleType()
{
    //This requests that the module be called every getDesiredScheduleRate() number of seconds
    return CALL_ON_NUM_SECONDS;
}*/

/** 
 * @brief Get the desired scheduling rate, which is used with getDesiredScheduleType
 * 
 * This method must be implemented for CALL_ON_NUM_TEST_CASE_EXECUTIONS and 
 * CALL_ON_NUMSECONDS in order to specify the desired schedule rate.  The default 
 * implementation returns 0.
 * 
 * See getDesiredScheduleType() for more information how this method is used.
 * 
 * @return int the desired scheduling rate
 */
/*int TemplateOutput::getDesiredScheduleRate()
{
    //Requests that the module be called every 10s
    return 10;
}*/