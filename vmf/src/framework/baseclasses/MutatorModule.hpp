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

#include "StorageUserModule.hpp"
#include "StorageEntry.hpp"

namespace vader
{
/**
 * @brief The base class for all Vader mutator modules.
 *
 * Mutator modules create a test case by mutating an existing test case.
 *
 */
class MutatorModule: public StorageUserModule
{
public:
    virtual void registerStorageNeeds(StorageRegistry& registry) = 0;
    virtual void registerMetadataNeeds(StorageRegistry& registry) {};
    /**
     * @brief Main method for a mutator module
     * This method should create a new test case, using the provided
     * baseEntry as starting point for mutation.
     * 
     * @param storage the storage module
     * @param baseEntry the base entry to mutate from
     * @return StorageEntry* the new test case
     */
    virtual StorageEntry* createTestCase(StorageModule& storage, StorageEntry* baseEntry) = 0;
    virtual ~MutatorModule() {};

  /**
     * @brief Helper method to return a single Mutator submodule from config
     * This method will retrieve a single Mutator submodules for the specified parent modules.
     * If there are no Mutator submodules, then an nullptr will be returned.  If there are more
     * than one Mutator submodules specified, than an exception will be thrown.  Use the list form
     * of this method getMutatorSubmodules(), if more than one Mutator module can be specified.
     * 
     * @param config the ConfigInterface object
     * @param parentName the name of the parent module
     * @return MutatorModule* the submodule, or nullptr if none is specified
     */
    static MutatorModule* getMutatorSubmodule(ConfigInterface& config, std::string parentName)
    {
        MutatorModule* theModule = nullptr;
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
                        "Configuration file contained more than one Mutator module, but only one is supported",
                        RuntimeException::CONFIGURATION_ERROR);
                }
                
            }
        }
        return theModule;
    }

    /**
     * @brief Helper method to get the Mutator Submodules from config
     * This method will retrieve all of the Mutator submodules for the specified parent modules.
     * If there are no Mutator submodules, then an empty list will be returned.
     * 
     * @param config the ConfigInterface object
     * @param parentName the name of the parent module
     * @return std::vector<MutatorModule*> the list of submodules
     */
    static std::vector<MutatorModule*> getMutatorSubmodules(ConfigInterface& config, std::string parentName)
    {
        std::vector<MutatorModule*> list;
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
     * @brief Convenience method to determine if a module is actually a mutator
     * 
     * @param module 
     * @return true if this module has a module type=MUTATOR
     * @return false 
     */
    static bool isAnInstance(Module* module)
    {
        ModuleTypeEnum type = module->getModuleType();
        return (ModuleTypeEnum::MUTATOR == type);
    }

    /**
     * @brief Convenience method to cast Module* to MutatorModule*
     * 
     * Call isAnInstance first to check the type in order to avoid an exception.
     * 
     * @param module 
     * @return MutatorModule* 
     * @throws RuntimeException if the underlying Module* is not a decendant of MutatorModule
     */
    static MutatorModule* castTo(Module* module)
    {
        MutatorModule* mut;
        if(nullptr != module)
        {
            mut = dynamic_cast<MutatorModule*>(module);
        
            if(nullptr == mut)
            {
                throw RuntimeException("Failed attempt to cast module to Mutator",
                                    RuntimeException::USAGE_ERROR);
            }
        }
        else
        {
            throw RuntimeException("Attempt to cast nullptr to Mutator",
                                   RuntimeException::UNEXPECTED_ERROR);
        }
        return mut;
    }

protected:
    /**
     * @brief Construct a new Mutator Module object
     * 
     * @param name the name of the module
     */
    MutatorModule(std::string name) : StorageUserModule(name, ModuleTypeEnum::MUTATOR) {};
};
}

