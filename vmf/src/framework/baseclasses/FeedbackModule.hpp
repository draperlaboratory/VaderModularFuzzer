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

#include "ExecutorModule.hpp"
#include "StorageUserModule.hpp"
#include "StorageEntry.hpp"

namespace vader
{
/**
 * @brief The base class for all Vader feedback modules.
 *
 * Feedback modules evalute the results of running a test case and determine how
 * good those results are.  The feedback module is responsible for determining whether or not
 * test cases should be maintained in long term storage, based on the information
 * that an executor provides about the test case execution results.
 * 
 * Typically the feedback module will write the sortByKey value that is used to
 * sort storage.
 */
class FeedbackModule: public StorageUserModule
{
public:
    virtual void registerStorageNeeds(StorageRegistry& registry) = 0;
    virtual void registerMetadataNeeds(StorageRegistry& registry) {};

    /**
     * @brief Set the ExecutorModule object
     * Each feedback module will need access to the test execution results
     * in order to evaluate them.  These are retrieve directly from the executor.
     * Often a downcast to a compatible execution is needed in the implementation, as execution 
     * results are specific to the executor type.
     * 
     * @param executor 
     */
    virtual void setExecutor(ExecutorModule* executor) = 0;

    /**
     * @brief Evaluate the test case results
     * This method must:
     * 1) compute and save the fitness value to the storage entry
     * 2) save any other values of interest to the storage entry, including tagging the entry if relevant
     * 3) determine if the test case is interesting enough to save in long term storage (and save the entry if it is)
     * 4) write any metadata metrics to storage (e.g. total number of crashes)
     * 
     * @param storage 
     * @param e 
     * @return true if the test case is interesting enough to be saved
     * @return false if it is not
     */
    virtual bool evaluateTestCaseResults(StorageModule& storage, StorageEntry* e) = 0;
    virtual ~FeedbackModule() {};
    
      /**
     * @brief Helper method to return a single Feedback submodule from config
     * This method will retrieve a single Feedback submodules for the specified parent modules.
     * If there are no Feedback submodules, then an nullptr will be returned.  If there are more
     * than one Feedback submodules specified, than an exception will be thrown.  Use the list form
     * of this method getFeedbackSubmodules(), if more than one Feedback module can be specified.
     * 
     * @param config the ConfigInterface object
     * @param parentName the name of the parent module
     * @return FeedbackModule* the submodule, or nullptr if none is specified
     */
    static FeedbackModule* getFeedbackSubmodule(ConfigInterface& config, std::string parentName)
    {
        FeedbackModule* theModule = nullptr;
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
                        "Configuration file contained more than one Feedback module, but only one is supported",
                        RuntimeException::CONFIGURATION_ERROR);
                }
                
            }
        }
        return theModule;
    }

    /**
     * @brief Helper method to get the Feedback Submodules from config
     * This method will retrieve all of the Feedback submodules for the specified parent modules.
     * If there are no Feedback submodules, then an empty list will be returned.
     * 
     * @param config the ConfigInterface object
     * @param parentName the name of the parent module
     * @return std::vector<FeedbackModule*> the list of submodules
     */
    static std::vector<FeedbackModule*> getFeedbackSubmodules(ConfigInterface& config, std::string parentName)
    {
        std::vector<FeedbackModule*> list;
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
     * @brief Convenience method to determine if a module is actually a Feedback module
     * 
     * @param module 
     * @return true if this module has a module type=Feedback
     * @return false 
     */
    static bool isAnInstance(Module* module)
    {
        ModuleTypeEnum type = module->getModuleType();
        return (ModuleTypeEnum::FEEDBACK == type);
    }

    /**
     * @brief Convenience method to cast Module* to FeedbackModule*
     * 
     * Call isAnInstance first to check the type in order to avoid an exception.
     * 
     * @param module 
     * @return FeedbackModule* 
     * @throws RuntimeException if the underlying Module* is not a decendant of FeedbackModule
     */
    static FeedbackModule* castTo(Module* module)
    {
        FeedbackModule* f;
        if(nullptr != module)
        {
            f = dynamic_cast<FeedbackModule*>(module);
        
            if(nullptr == f)
            {
                throw RuntimeException("Failed attempt to cast module to Feedback",
                                    RuntimeException::USAGE_ERROR);
            }
        }
        else
        {
            throw RuntimeException("Attempt to cast nullptr to Feedback",
                                   RuntimeException::UNEXPECTED_ERROR);
        }
        return f;
    }

protected:
    /**
     * @brief Construct a new Feedback Module object
     * 
     * @param name the name of the module
     */
    FeedbackModule(std::string name) : StorageUserModule(name, ModuleTypeEnum::FEEDBACK) {};
};
}