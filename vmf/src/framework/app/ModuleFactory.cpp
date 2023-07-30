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
#include "Logging.hpp"
#include "RuntimeException.hpp"
#include "ModuleFactory.hpp"

using namespace vader;

ModuleFactory::ModuleFactory()
{
}

/**
 * @brief Registers a module with the module factory
 * Implementers of a module should use the REGISTER_MODULE macro instead
 * of directly calling this method
 * 
 * @param className the class name for the module (this should match the actual class name)
 * @param buildFunc the builder function
 */
void ModuleFactory::registerModule(std::string className, TModuleBuildMethod buildFunc)
{
    factoryMap.insert(std::pair<std::string,TModuleBuildMethod>(className, buildFunc));
}

/**
 * @brief Build the specified module
 * 
 * The className provides must match a module that has been registered with the factory.
 * This should happen automatically as long as all module developers properly register
 * their modules with the REGISTER_MODULE macro.
 * 
 * @param className the class name of the module
 * @param name the unique name to use for the module
 * @return Module* a pointer to the module
 * @throws RuntimeException if the module className is unknown
 */
Module* ModuleFactory::buildModule(std::string className, std::string name)
{
    TModuleBuildMethod builderFunc = factoryMap[className]; 
    if(nullptr==builderFunc)
    {
       LOG_ERROR << "UNKNOWN MODULE:" << className;
       throw RuntimeException("Unknown module specified, unable to build",
                              RuntimeException::CONFIGURATION_ERROR);
    }
    
    return (*builderFunc)(name); //call the builder method
}

/**
 * @brief Accessor for the singleton ModuleFactory
 * 
 * @return ModuleFactory& the singleton
 */
ModuleFactory &ModuleFactory::getInstance() {
    static ModuleFactory instance;
    return instance;
}

/**
 * @brief Construct a new Module Registrar object
 * 
 * A static instnce of this class is created by the REGISTER_MODULE macro 
 * in order to register modules automatically.
 * 
 * @param className the class name for the module
 * @param buildFunc the builder function
 */
ModuleRegistrar::ModuleRegistrar(std::string className, ModuleFactory::TModuleBuildMethod buildFunc)
{
    LOG_INFO << "registering module " << className << "\n";
    ModuleFactory::getInstance().registerModule(className, buildFunc);
}
