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
#include "Module.hpp"
#include "StorageRegistry.hpp"
#include "StorageModule.hpp"
#include "ConfigInterface.hpp"
#include <map>

namespace vmf
{
/**
 * @brief A helper class that manages the set of modules
 * This class supports the management of the set of modules that is instantiated
 * within VMF.
 */
class ModuleManager 
{
public:
    ModuleManager();
    ~ModuleManager();
    Module* buildModule(std::string className, std::string name);
    bool containsModule(std::string name);
    Module* getModule(std::string name);
    std::string getModuleName(int id);
    Module* getRootModule();
    Module* getStorageModule();
    void setRootModule(Module* root);
    void setStorageModule(Module* storage);

    void initializeModules(ConfigInterface& config);
    void registerModuleStorageNeeds(StorageRegistry* registry, StorageRegistry* metadata);
    void shutdownModules(StorageModule& storage);
    void deleteModules();
private:
    void callShutdown(Module* module, StorageModule& storage);
    std::map<std::string, Module*> moduleList;
    Module* rootModule;
    Module* storageModule;
};
}
