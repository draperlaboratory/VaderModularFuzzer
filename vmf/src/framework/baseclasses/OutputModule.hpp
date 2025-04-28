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


#include "StorageUserModule.hpp"
#include "Logging.hpp"

namespace vmf
{
/**
 * @brief Base class for VMF output modules
 *
 * Output modules are used to examine the results of test cases.  They are fairly 
 * general purpose and may be used to output information to a human operator, to 
 * trim the corpus of test cases, or to perform any other function that should occur 
 * periodically as test cases execute. OutputModules are schedulable, and indicate a preferred 
 * scheduling rate to the Controller managing them.
 */
class OutputModule : public StorageUserModule {
public:

    ///The list of ways that OutputModules can be scheduled
    enum ScheduleTypeEnum
    {
        CALL_EVERYTIME,
        CALL_ON_NUM_SECONDS,
        CALL_ON_NUM_TEST_CASE_EXECUTIONS,
        CALL_ONLY_ON_SHUTDOWN
    };

    virtual void registerStorageNeeds(StorageRegistry& registry) = 0;
    virtual void registerMetadataNeeds(StorageRegistry& registry) {};

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
    virtual void run(StorageModule& storage) = 0;

    /** @brief Perform any shutdown output processing
     * 
     * Many output modules may wish to peform special processing when the controller is
     * shutdown (such as writing any final data to disk, or running one more time on
     * any outputs that haven't been processed yet).  This method is optional.
     * 
     * @param storage 
     */
    virtual void shutdown(StorageModule& storage) {};

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
    virtual ScheduleTypeEnum getDesiredScheduleType()
    {
        return CALL_EVERYTIME;
    }

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
    virtual int getDesiredScheduleRate()
    {
        return 0;
    }

    virtual ~OutputModule() {};

  /**
     * @brief Helper method to return a single Output submodule from config
     * This method will retrieve a single Output submodules for the specified parent modules.
     * If there are no Output submodules, then an nullptr will be returned.  If there are more
     * than one Output submodules specified, than an exception will be thrown.  Use the list form
     * of this method getOutputSubmodules(), if more than one Output module can be specified.
     * 
     * @param config the ConfigInterface object
     * @param parentName the name of the parent module
     * @return OutputModule* the submodule, or nullptr if none is specified
     */
    static OutputModule* getOutputSubmodule(ConfigInterface& config, std::string parentName)
    {
        OutputModule* theModule = nullptr;
        std::vector<Module*> modules = config.getSubModules(parentName);
        for(Module* m: modules)
        {
            if(isAnInstance(m))
            {
                if(nullptr == theModule)
                {
                    theModule = castTo(m);
                }
                else
                {
                    throw RuntimeException(
                        "Configuration file contained more than one Output module, but only one is supported",
                        RuntimeException::CONFIGURATION_ERROR);
                }
                
            }
        }
        return theModule;
    }

    /**
     * @brief Helper method to return a single Output submodule from config by name
     * This method will retrieve a single Output submodule by name for the specified parent modules.
     * If there are no Output submodules with the specified name, then an nullptr will be returned.  
     * 
     * @param config the ConfigInterface object
     * @param parentName the name of the parent module
     * @param childName the name of the child module to finde
     * @return OutputModule* the submodule, or nullptr if none is found
     */
    static OutputModule* getOutputSubmoduleByName(ConfigInterface& config, std::string parentName, std::string childName)
    {
        OutputModule* theModule = nullptr;
        std::vector<Module*> modules = config.getSubModules(parentName);
        for(Module* m: modules)
        {
            if(childName == m->getModuleName())
            {
                if(isAnInstance(m))
                {
                    theModule = castTo(m);
                    break;
                }
                else
                {
                    LOG_ERROR << parentName << " requested an Output submodule named " << childName 
                               << ", but that submodules is not of type Output.";
                    throw RuntimeException(
                        "Configuration file contained a module with this name, but it was not an executor module",
                        RuntimeException::CONFIGURATION_ERROR);
                }
            }
        }
        return theModule;
    }

    /**
     * @brief Helper method to get the Output Submodules from config
     * This method will retrieve all of the Output submodules for the specified parent modules.
     * If there are no Output submodules, then an empty list will be returned.
     * 
     * @param config the ConfigInterface object
     * @param parentName the name of the parent module
     * @return std::vector<OutputModule*> the list of submodules
     */
    static std::vector<OutputModule*> getOutputSubmodules(ConfigInterface& config, std::string parentName)
    {
        std::vector<OutputModule*> list;
        std::vector<Module*> modules = config.getSubModules(parentName);
        for(Module* m: modules)
        {
            if(isAnInstance(m))
            {
                list.push_back(castTo(m));
            }
        }
        return list;
    }


    /**
     * @brief Convenience method to determine if a module is actually an output module
     * 
     * @param module 
     * @return true if this module has a module type=OUTPUT
     * @return false 
     */
    static bool isAnInstance(Module* module)
    {
        ModuleTypeEnum type = module->getModuleType();
        return (ModuleTypeEnum::OUTPUT == type);
    }

    /**
     * @brief Convenience method to cast Module* to OutputModule*
     * 
     * Call isAnInstance first to check the type in order to avoid an exception.
     * 
     * @param module 
     * @return OutputModule* 
     * @throws RuntimeException if the underlying Module* is not a decendant of OutputModule
     */
    static OutputModule* castTo(Module* module)
    {
        OutputModule* out;
        if(nullptr != module)
        {
            out = dynamic_cast<OutputModule*>(module);
        
            if(nullptr == out)
            {
                throw RuntimeException("Failed attempt to cast module to Output",
                                    RuntimeException::USAGE_ERROR);
            }
        }
        else
        {
            throw RuntimeException("Attempt to cast nullptr to Output",
                                   RuntimeException::UNEXPECTED_ERROR);
        }
        return out;
    }

protected:
    /**
     * @brief Construct a new Output Module object
     * 
     * @param name the module name
     */
    OutputModule(std::string name) : StorageUserModule(name, ModuleTypeEnum::OUTPUT) {};
};
}