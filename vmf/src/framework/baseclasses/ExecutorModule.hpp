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
#include "RuntimeException.hpp"
#include "Logging.hpp"
#include <memory>

namespace vmf
{
/**
 * @brief The base class for all VMF Executors
 *
 * Executore modules run the SUT using each test case as an input and capture the 
 * results of that execution in storage. This includes evaluating the bug oracle.
 *
 */
class ExecutorModule : public StorageUserModule
{
public:
 
    /**
     * @brief Method that runs the provided test case on the SUT
     * 
     * Any test results must be written to the storage entry.
     * The specific data collected will depend on the executor, but in general
     * includes information like whether the test case crashed or not and how
     * long it took to execute.
     * 
     * @param storage 
     * @param entry the entry to execute
     */
    virtual void runTestCase(StorageModule& storage, StorageEntry* entry) = 0;

    /**
     * @brief Method that runs the provided list of test cases on the SUT
     * 
     * This is an optional method.  The default implementation of this method
     * will simply call runTestCase() for every new entry in storage.  Executors
     * need only override this method if they do something other than run each of the
     * entries individually (for example, a batch execution capability would 
     * likely require overriding this method).
     * 
     * @param storage 
     * @param iterator 
     */
    virtual void runTestCases(StorageModule& storage, std::unique_ptr<Iterator>& iterator)
    {
        while(iterator->hasNext())
        {
            StorageEntry* entry = iterator->getNext();
            runTestCase(storage, entry);
        }
    }

    /**
     * @brief Method that runs the provided test case in callibration mode
     * This method is optional.  But it will be called once with the initial
     * seed test cases, and should be used for any callibration that requires
     * sample test cases (such as determining a reasonable execution time for a test case).
     * 
     * @param storage the reference to storage 
     * @param iterator an iterator that contains the initial seed test cases 
     */
    virtual void runCalibrationCases(StorageModule& storage, std::unique_ptr<Iterator>& iterator) {};


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
     * @brief Helper method to return a single Executor submodule from config by name
     * This method will retrieve a single Executor submodule by name for the specified parent modules.
     * If there are no Executor submodules with the specified name, then an nullptr will be returned.  
     * 
     * @param config the ConfigInterface object
     * @param parentName the name of the parent module
     * @param childName the name of the child module to finde
     * @return ExecutorModule* the submodule, or nullptr if none is found
     */
    static ExecutorModule* getExecutorSubmoduleByName(ConfigInterface& config, std::string parentName, std::string childName)
    {
        ExecutorModule* theModule = nullptr;
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
                    LOG_ERROR << parentName << " requested an Executor submodule named " << childName 
                               << ", but that submodules is not of type Executor.";
                    throw RuntimeException(
                        "Configuration file contained a module with this name, but it was not an executor module",
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
    ExecutorModule(std::string name) : StorageUserModule(name, ModuleTypeEnum::EXECUTOR) {};
};
}

