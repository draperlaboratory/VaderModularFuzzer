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
#include "ModuleTestHelper.hpp"
#include "StorageUserModule.hpp"
#include "SimpleStorage.hpp"

using namespace vmf;


ModuleTestHelper::ModuleTestHelper()
{
    hasBeenInitialized = false;
    storage = new SimpleStorage("storage");
    //This is the default configuration of the storage registry
    registry = new StorageRegistry("FITNESS", StorageRegistry::FLOAT, StorageRegistry::DESCENDING);
    //Go ahead and registry for the fitness key, as otherwise modules that don't use fitness will
    //not be able to initialize storage (fitness is required, as it is the sort by key)
    registry->registerKey("FITNESS", StorageRegistry::FLOAT, StorageRegistry::WRITE_ONLY);
    metadata = new StorageRegistry();
}

ModuleTestHelper::~ModuleTestHelper()
{
    delete registry;
    delete metadata;
    delete storage;
    for(Module* m: modules)
    {
        delete m;
    }
    modules.clear();
}

/**
 * @brief Adds modules to the list of modules that should be initialized
 * This method must be called prior to initializeModulesAndStorage.  Attempts
 * to call it after the call to initializeModulesAndStorage will result in an exception.
 * 
 * @param module the module to add
 * @throws RuntimeException if this method is called after initializeModulesAndStorage
 */
void ModuleTestHelper::addModule(Module* module)
{
    if(!hasBeenInitialized)
    {
        modules.push_back(module);
    }
    else
    {
        throw RuntimeException("Modules can't be added after call to initializeModules", RuntimeException::USAGE_ERROR);
    }

}

/**
 * @brief Initializes storage and all modules that have been added
 * Be sure to manually register for any additional parameters that will
 * be written by the test harness, otherwise the storage registration will
 * not be valid.
 * 
 * @throws RuntimeException if the storage registration is not valid, or if this
 * method is called twice
 */
void ModuleTestHelper::initializeModulesAndStorage()
{
    if(!hasBeenInitialized)
    {
        hasBeenInitialized = true;
        storage->init(config);
        for(Module* module: modules)
        {
            module->init(config);
            StorageUserModule* sum = dynamic_cast<StorageUserModule*>(module);
            if(nullptr != sum)
            {
                sum->registerMetadataNeeds(*metadata);
                sum->registerStorageNeeds(*registry);
            }
        }

        bool valid = registry->validateRegistration();
        if(!valid)
        {
            throw RuntimeException("Storage registration is not valid -- is something read that isn't written?", 
                                RuntimeException::CONFIGURATION_ERROR);
        }
        valid = metadata->validateRegistration();
        if(!valid)
        {
            throw RuntimeException("Storage metadata registration is not valid -- is something read that isn't written?", 
                                RuntimeException::CONFIGURATION_ERROR);
        }
        storage->configure(registry, metadata);
    }
    else
    {
        throw RuntimeException("initializeModulesAndStorage can only be called once", RuntimeException::USAGE_ERROR);
    }
}

/**
 * @brief Returns the config object
 * Use this object to manually set any configuration information needed by your unit test
 * 
 * @return TestConfigInterface*
 */
TestConfigInterface* ModuleTestHelper::getConfig()
{
    return &config;
}

/**
 * @brief Returns the storage modules
 * Use this object to set and check any data that should be in storage to support your unit test
 * 
 * @return StorageModule*
 */
StorageModule* ModuleTestHelper::getStorage()
{
    return storage;
}

/**
 * @brief Returns the storage registry object
 * Use this object to manually register for any additional data written by your unit test.
 * Values must be set prior to the call to initializeModulesAndStorage.
 * 
 * @return StorageRegistry*
 * @throws RuntimeException if this method is called after initializeModulesAndStorage
 */
StorageRegistry* ModuleTestHelper::getRegistry()
{
    if(!hasBeenInitialized)
    {
        return registry;
    }
    else
    {
        throw RuntimeException("You can't register for more data after initializeModulesAndStorage has been called", 
                               RuntimeException::USAGE_ERROR);
    }
}

/**
 * @brief Returns the metadata storage registry object
 * Use this object to manually register for any additional metadata written by your unit test.
 * Values must be set prior to the call to initializeModulesAndStorage.
 * 
 * @return StorageRegistry*
 * @throws RuntimeException if this method is called after initializeModulesAndStorage
 */
StorageRegistry* ModuleTestHelper::getMetadataRegistry()
{
    if(!hasBeenInitialized)
    {
        return metadata;
    }
    else
    {
        throw RuntimeException("You can't register for more metadata after initializeModulesAndStorage has been called", 
                               RuntimeException::USAGE_ERROR);
    }
}


