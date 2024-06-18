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
#include "ModuleManager.hpp"
#include "ModuleFactory.hpp"
#include "StorageUserModule.hpp"
#include "Logging.hpp"
#include "RuntimeException.hpp"

using namespace vmf;

ModuleManager::ModuleManager()
{
    rootModule = nullptr;
    storageModule = nullptr;
}

ModuleManager::~ModuleManager()
{
    deleteModules();
}

/**
 * @brief Build a new module (and store it internally)
 * The name parameter is the name that the module will be referred to by.
 * This must be a unique name in each configuration.
 * 
 * @param className the name of the class
 * @param name the name of the module
 * @returns a pointer to the new module
 * @throws RuntimeException if the module name is not unique
 */
Module* ModuleManager::buildModule(std::string className, std::string name)
{
    //Check that the name is not already defined in the registry
    if(moduleList.count(name)>0)
    {
        LOG_ERROR << "VMF configuration contains more than one module named " << name;
        throw RuntimeException("Duplicate module name in the configuration.", RuntimeException::CONFIGURATION_ERROR);
    }

    //Build module and add to registry
    Module* newModule = ModuleFactory::getInstance().buildModule(className, name);
    moduleList[name] = newModule;
    LOG_INFO << "LOADING: " << name << " module (instance of " << className << ")"; 

    return newModule;
}

/**
 * @brief Check to see if a module has been registered with this name
 * 
 * @param name the name to lookup
 * @return true if a module has been registered with this name
 * @return false otherwise
 */
bool ModuleManager::containsModule(std::string name)
{
    bool found = false;
    if(moduleList.count(name)>0)
    {
        found = true;
    }
    return found;
}

/**
 * @brief Lookup module by name
 * 
 * @param name the name to lookup
 * @return Module* the pointer to the module
 * @throws RuntimeException if the module cannot be found
 */
Module* ModuleManager::lookupModule(std::string name)
{
    Module* m = moduleList[name];
    if(nullptr == m)
    {
        LOG_ERROR << "UNKNOWN MODULE:" << name;
        throw RuntimeException("Unknown module name included in config",
                               RuntimeException::CONFIGURATION_ERROR);
    }
    return m;
}


/**
 * @brief Returns the root module
 * 
 * @return Module* the root module
 * @throws RuntimException if there is  module
 */
Module* ModuleManager::getRootModule()
{
    if(nullptr == rootModule)
    {
        throw RuntimeException("No root module defined in the config file.", RuntimeException::CONFIGURATION_ERROR);
    }
    return rootModule;
}

/**
 * @brief Returns the storage module
 * 
 * @return Module* the storage module
 * @throws RuntimException if there is no storage module
 */
Module* ModuleManager::getStorageModule()
{ 
    if(nullptr == storageModule)
    {
        throw RuntimeException("No storage module defined in the config file.", RuntimeException::CONFIGURATION_ERROR);
    }
    return storageModule;
}

/**
 * @brief Set the root module
 * 
 * @param root the module pointer
 */
void ModuleManager::setRootModule(Module* root)
{
    rootModule = root;
}

/**
 * @brief Set the storage module
 * 
 * @param storage the module pointer
 */
void ModuleManager::setStorageModule(Module* storage)
{
    storageModule = storage;
}

/**
 * @brief Delete all of the built modules and clear the module registry
 * This is called automatically in the destructor, but may also be called at other
 * times to fully clear the currently loaded modules.
 */
void ModuleManager::deleteModules()
{
    //Delete all of the built modules
    for (const auto &module : moduleList) 
    {
        Module* mPtr = module.second;
        delete mPtr;
    }

    moduleList.clear();
}

/**
 * @brief Call the init() method on every module in the registry
 * @param config the ConfigInterface instance to provide to each module
 */
void ModuleManager::initializeModules(ConfigInterface& config)
{
   //Now initialize all of the modules that were just build
   for (const auto &module : moduleList) {

        Module* m = module.second;
        LOG_DEBUG << "   INITIALIZING: " << module.first;
        m->init(config);
    }
}


/**
 * @brief Call upon all of the StorageUserModules to register their storage needs
 * Note: initializeModules() must be called first, otherwise there are no initialized
 * modules yet to register with storage.
 * This method calls registerStorageNeeds() and registerMetadataNeeds() on each
 * StorageUserModule that has been loaded.
 * 
 * @param registry the main storage registry
 * @param metadata the metadata storage registry
 */
void ModuleManager::registerModuleStorageNeeds(StorageRegistry* registry, StorageRegistry* metadata)
{
    for (const auto &module : moduleList) 
    {
        Module* m = module.second;
        StorageUserModule* sum = dynamic_cast<StorageUserModule*>(m);
        if(nullptr != sum)
        {
            sum->registerStorageNeeds(*registry);
            sum->registerMetadataNeeds(*metadata);
        }
        //otherwise this is a Module that is not a subclass of StorageUserModule
        //and hence it has no storage needs to be registered
            
    }
}

/**
 * @brief Call upon all of the modules to shutdown
 * 
 * This method calls shutdown on all module types, and shutdown(storage)
 * on all StorageUserModules.  No order is specified for these calls *except* that
 * the root module will be shutdown second to last, and the storage module will
 * be shutdown last.
 * 
 * @param storage storage module to provide at shutdown (this could technically
 * be retrieved by this module, but the caller will have this information more
 * readily accessible)
 */
void ModuleManager::shutdownModules(StorageModule& storage)
{
    for (const auto &module : moduleList) 
    {
        std::string key = module.first;
        //If this is the storage or root module, save it for the end
        if((storageModule->getModuleName() != key)&&(rootModule->getModuleName() != key))
        {
            callShutdown(module.second, storage);
        }
            
    }

    //Now shutdown the root module and storage module (assuming we have one)
    if(nullptr != rootModule)
    {
        callShutdown(rootModule,storage);
    }
    if(nullptr != storageModule)
    {
        storageModule->shutdown(); //the storage module cannot be a storage user, by definition
    }
}

/**
 * @brief Helper method to call the shutdown methods on the specified module
 * 
 * @param module the module to shutdown
 * @param storage the storage module to pass to shutdown(storage) for StorageUserModules
 */
void ModuleManager::callShutdown(Module* module, StorageModule& storage)
{
    //Call shutdown
    module->shutdown();

    //If this is a StorageUserModule, call storage(shutdown) as well
    StorageUserModule* sum = dynamic_cast<StorageUserModule*>(module);
    if(nullptr != sum)
    {
        sum->shutdown(storage);
    }
}