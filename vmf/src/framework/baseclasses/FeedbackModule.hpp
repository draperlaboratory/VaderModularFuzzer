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
#include "StorageEntry.hpp"
#include "Iterator.hpp"
#include "Logging.hpp"

namespace vmf
{
/**
 * @brief The base class for all VMF feedback modules.
 *
 * Feedback modules evaluate the results of running a test case and determine whether 
 * the test case is interesting enough to keep in long term storage.  This decision is 
 * made based on the information that an executor provides about the test case execution results.  
 * Typically feedback modules will also write the sortByKey value that is used to sort test cases 
 * in long term storage.
 */
class FeedbackModule: public StorageUserModule
{
public:
    virtual void registerStorageNeeds(StorageRegistry& registry) = 0;
    virtual void registerMetadataNeeds(StorageRegistry& registry) {};

    /**
     * @brief Evaluate the test case results
     * This method must:
     * 1) compute and save the sort by key (e.g fitness) to the storage entry
     * 2) save any other values of interest to the storage entry, including tagging the entry if relevant
     * 3) determine if the test case is interesting enough to save in long term storage (and save the entry if it is)
     * 
     * @param storage 
     * @param entries 
     */
    virtual void evaluateTestCaseResults(StorageModule& storage, std::unique_ptr<Iterator>& entries) = 0;
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
     * @brief Helper method to return a single Feedback submodule from config by name
     * This method will retrieve a single Feedback submodule by name for the specified parent modules.
     * If there are no Feedback submodules with the specified name, then an nullptr will be returned.  
     * 
     * @param config the ConfigInterface object
     * @param parentName the name of the parent module
     * @param childName the name of the child module to finde
     * @return FeedbackModule* the submodule, or nullptr if none is found
     */
    static FeedbackModule* getFeedbackSubmoduleByName(ConfigInterface& config, std::string parentName, std::string childName)
    {
        FeedbackModule* theModule = nullptr;
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
                    LOG_ERROR << parentName << " requested an Feedback submodule named " << childName 
                               << ", but that submodules is not of type Feedback.";
                    throw RuntimeException(
                        "Configuration file contained a module with this name, but it was not an executor module",
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