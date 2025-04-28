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
 * @brief Base class for VMF Initialization modules
 *
 * Initialization modules are run once, prior to the main fuzzing loop.  
 * They are typically used to manage seeds, either loading, generating, or selecting seeds.  
 * Static instrumention of the SUT is performed outside of VMF, prior to starting the fuzzer.  Model 
 * preparation for input generation is typically done as part of the input generator itself.
 *
 */
class InitializationModule: public StorageUserModule {
public:
    virtual void registerStorageNeeds(StorageRegistry& registry) = 0;
    virtual void registerMetadataNeeds(StorageRegistry& registry) {};

    /**
     * @brief Perform any initialization
     * This method is the meat of the initialization module.  It should
     * perform any designed initialization steps (e.g. seed generation).
     * This is only called once, upfront, before other modules are called
     * upon to run.
     * 
     * @param storage 
     */
    virtual void run(StorageModule& storage) = 0;
    virtual ~InitializationModule() {};

  /**
     * @brief Helper method to return a single Initialization submodule from config
     * This method will retrieve a single Initialization submodules for the specified parent modules.
     * If there are no Initialization submodules, then an nullptr will be returned.  If there are more
     * than one Initialization submodules specified, than an exception will be thrown.  Use the list form
     * of this method getInitializationSubmodules(), if more than one Initialization module can be specified.
     * 
     * @param config the ConfigInterface object
     * @param parentName the name of the parent module
     * @return InitializationModule* the submodule, or nullptr if none is specified
     */
    static InitializationModule* getInitializationSubmodule(ConfigInterface& config, std::string parentName)
    {
        InitializationModule* theModule = nullptr;
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
                        "Configuration file contained more than one Initialization module, but only one is supported",
                        RuntimeException::CONFIGURATION_ERROR);
                }
                
            }
        }
        return theModule;
    }

    /**
     * @brief Helper method to return a single Initialization submodule from config by name
     * This method will retrieve a single Initialization submodule by name for the specified parent modules.
     * If there are no Initialization submodules with the specified name, then an nullptr will be returned.  
     * 
     * @param config the ConfigInterface object
     * @param parentName the name of the parent module
     * @param childName the name of the child module to finde
     * @return InitializationModule* the submodule, or nullptr if none is found
     */
    static InitializationModule* getInitializationSubmoduleByName(ConfigInterface& config, std::string parentName, std::string childName)
    {
        InitializationModule* theModule = nullptr;
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
                    LOG_ERROR << parentName << " requested an Initialization submodule named " << childName 
                               << ", but that submodules is not of type Initialization.";
                    throw RuntimeException(
                        "Configuration file contained a module with this name, but it was not an executor module",
                        RuntimeException::CONFIGURATION_ERROR);
                }
            }
        }
        return theModule;
    }

    /**
     * @brief Helper method to get the Initialization Submodules from config
     * This method will retrieve all of the Initialization submodules for the specified parent modules.
     * If there are no Initialization submodules, then an empty list will be returned.
     * 
     * @param config the ConfigInterface object
     * @param parentName the name of the parent module
     * @return std::vector<InitializationModule*> the list of submodules
     */
    static std::vector<InitializationModule*> getInitializationSubmodules(ConfigInterface& config, std::string parentName)
    {
        std::vector<InitializationModule*> list;
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
     * @brief Convenience method to determine if a module is actually a Initialization module
     * 
     * @param module 
     * @return true if this module has a module type=INITIALIZATION
     * @return false 
     */
    static bool isAnInstance(Module* module)
    {
        ModuleTypeEnum type = module->getModuleType();
        return (ModuleTypeEnum::INITIALIZATION == type);
    }

    /**
     * @brief Convenience method to cast Module* to InitializationModule*
     * 
     * Call isAnInstance first to check the type in order to avoid an exception.
     * 
     * @param module 
     * @return InitializationModule* 
     * @throws RuntimeException if the underlying Module* is not a decendant of InitializationModule
     */
    static InitializationModule* castTo(Module* module)
    {
        InitializationModule* init;
        if(nullptr != module)
        {
            init = dynamic_cast<InitializationModule*>(module);
        
            if(nullptr == init)
            {
                throw RuntimeException("Failed attempt to cast module to Initialization",
                                    RuntimeException::USAGE_ERROR);
            }
        }
        else
        {
            throw RuntimeException("Attempt to cast nullptr to Initialization",
                                   RuntimeException::UNEXPECTED_ERROR);
        }
        return init;
    }
protected:
    /**
     * @brief Construct a new Initialization Module object
     * 
     * @param name the name of the module
     */
    InitializationModule(std::string name) : StorageUserModule(name, ModuleTypeEnum::INITIALIZATION) {};
};
}
