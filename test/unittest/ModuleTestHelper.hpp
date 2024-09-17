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
#pragma once
#include "StorageModule.hpp"
#include "TestConfigInterface.hpp"

namespace vmf
{
/**
 * @brief Helper class for unit testing modules.
 * Helps with setup and initialization of modules and storage.  The expected usage pattern is:
 * 1. Construct a ModuleTestHelper object
 * 2. Add any modules that will be used in the unit test -- addModule()
 * 3. Add any configuration data that the modules need -- getConfig()
 * 4. Register for any storage data fields that will be written or read by the unit test 
 *    - Call getRegistry()/getMetataRegistry()
 *    - Use the registration methods to get a handle to the fields needed
 * 5. Call initializeModulesAndStorage()
 *    - The ModuleTest Helper will automatically initialize the module, call it's register storage needs
 *      methods, and validate the storage registration
 * 6. Proceed with the rest of the unit test
 *    -- use getStorage() to write data to storage and read values written by the module under test
 */
class ModuleTestHelper 
{
public:
    ModuleTestHelper();
    ~ModuleTestHelper();

    void addModule(Module* module);
    void initializeModulesAndStorage();

    TestConfigInterface* getConfig();
    StorageModule* getStorage();
    StorageRegistry* getRegistry();
    StorageRegistry* getMetadataRegistry();

private:
    bool hasBeenInitialized;
    StorageModule* storage;
    StorageRegistry* registry;
    StorageRegistry* metadata;
    TestConfigInterface config;
    std::vector<Module*> modules;
};
}