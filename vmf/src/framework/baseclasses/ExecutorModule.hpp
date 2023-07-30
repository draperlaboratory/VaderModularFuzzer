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

#include "Module.hpp"
#include "RuntimeException.hpp"
#include <memory>

namespace vader
{
/**
 * @brief The base class for all Vader Executors
 *
 * Executor modules are responsible for running test cases. 
 * This includes collecting any metrics about the test case.
 *
 */
class ExecutorModule : public Module
{
public:
 
    /**
     * @brief Method that runs the provided test case on the SUT
     * 
     * Any test results must be provided through additional accessor functions.
     * The specific data returned will depend on the executor, but in general
     * includes information like whether the test case crashed or not and how
     * long it took to execute.
     * 
     * @param buffer a pointer to the raw test case buffer to run
     * @param size the size of the buffer
     */
    virtual void runTestCase(char* buffer, int size) = 0; 

    /**
     * @brief Method that runs the provided test case in callibration mode
     * This method is optional.  But it will be called once for each of the 
     * initial test cases, and should be used for any callibration that requires
     * sample test cases (such as determining a reasonable execution time for a test case).
     * 
     * @param buffer 
     * @param size 
     */
    virtual void runCalibrationCase(char* buffer, int size) {};

    /**
     * @brief This method is called when callibration is complete.
     * This method is optional, but is generally implemented if runCalibrationCase is
     * implemented.  This method is called after each of the test cases has been provided
     * to runCalibrationCase.  Any summary calibration computations belong in this method.
     */
    virtual void completeCalibration() {};

    /**
     * @brief Destroy the Executor Module object
     */
    virtual ~ExecutorModule() {};

  /**
     * @brief Helper method to return a single Executor submodule from config
     * This method will retrieve a single Executor submodules for the specified parent modules.
     * If there are no Executor submodules, then an nullptr will be returned.  If there are more
     * than one Executor submodules specified, than an exception will be thrown.  Use the list form
     * of this method getExecutorSubmodules(), if more than one Executor module can be specified.
     * 
     * @param config the ConfigInterface object
     * @param parentName the name of the parent module
     * @return ExecutorModule* the submodule, or nullptr if none is specified
     */
    static ExecutorModule* getExecutorSubmodule(ConfigInterface& config, std::string parentName)
    {
        ExecutorModule* theModule = nullptr;
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
                        "Configuration file contained more than one Executor module, but only one is supported",
                        RuntimeException::CONFIGURATION_ERROR);
                }
                
            }
        }
        return theModule;
    }

    /**
     * @brief Helper method to get the Executor Submodules from config
     * This method will retrieve all of the Executor submodules for the specified parent modules.
     * If there are no Executor submodules, then an empty list will be returned.
     * 
     * @param config the ConfigInterface object
     * @param parentName the name of the parent module
     * @return std::vector<ExecutorModule*> the list of submodules
     */
    static std::vector<ExecutorModule*> getExecutorSubmodules(ConfigInterface& config, std::string parentName)
    {
        std::vector<ExecutorModule*> list;
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
     * @brief Convenience method to determine if a module is actually an executor
     * 
     * @param module 
     * @return true if this module has a module type=EXECUTOR
     * @return false 
     */
    static bool isAnInstance(Module* module)
    {
        ModuleTypeEnum type = module->getModuleType();
        return (ModuleTypeEnum::EXECUTOR == type);
    }

    /**
     * @brief Convenience method to cast Module* to ExecutorModule*
     * 
     * Call isAnInstance first to check the type in order to avoid an exception.
     * 
     * @param module 
     * @return ExecutorModule* 
     * @throws RuntimeException if the underlying Module* is not a decendant of ExecutorModule
     */
    static ExecutorModule* castTo(Module* module)
    {
        ExecutorModule* exec;
        if(nullptr != module)
        {
            exec = dynamic_cast<ExecutorModule*>(module);
        
            if(nullptr == exec)
            {
                throw RuntimeException("Failed attempt to cast module to Executor",
                                    RuntimeException::USAGE_ERROR);
            }
        }
        else
        {
            throw RuntimeException("Attempt to cast nullptr to Executor",
                                   RuntimeException::UNEXPECTED_ERROR);
        }
        return exec;
    }

protected:
    /**
     * @brief Construct a new Executor Module object
     * 
     * @param name the module name
     */
    ExecutorModule(std::string name) : Module(name, ModuleTypeEnum::EXECUTOR) {};
};
}

