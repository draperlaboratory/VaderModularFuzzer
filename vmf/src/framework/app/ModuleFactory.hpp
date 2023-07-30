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
#include "Module.hpp"
#include <map>

namespace vader
{
/**
 * @brief A singleton class that builds modules by name
 * A REGISTER_MODULE macro is provided for modules to easily register their
 * builder methods with the ModuleFactory.
 * 
 */
class ModuleFactory final
{
    /// Private to enforce the singleton pattern
    ModuleFactory();
public:
    /// deleted to enforce the singleton pattern
    ModuleFactory(ModuleFactory const &) = delete;
    /// deleted to enforce the singleton pattern
    void operator=(ModuleFactory const &) = delete;
    
    ///Type specification for the module builder method
    using TModuleBuildMethod = Module* (*)(std::string name);


    void registerModule(std::string className, TModuleBuildMethod buildFunc);
    Module* buildModule(std::string className, std::string name);

    // Returns a reference to the singleton instance of ModuleFactory
    static ModuleFactory &getInstance();

protected:
    ///A map of class names to builder methods
    std::map<std::string, TModuleBuildMethod> factoryMap;
};

/**
 * @brief Support class for automatic registration of modules with the ModuleFactory.
 * 
 * This class is used by the REGISTER_MODULE macro.
 * 
 */
struct ModuleRegistrar
{
    ModuleRegistrar(std::string className, ModuleFactory::TModuleBuildMethod buildFunc);

    /**
       This can be extended to unregister modules autmatically, if we ever want to support that.
     */
    ~ModuleRegistrar() { }
};

/**
 * @brief  Helper macro for registering VMF Modules. 
 * For a class implementing a VMF module, use this macro in the source file 
 * implementing the module to ensure your module is registered at application 
 * startup time.  For example, if your module is AFLForkserverExecturor, you would do this:
 *
 * REGISTER_MODULE(AFLForkserverExecutor);
 */
#define REGISTER_MODULE(name) static ModuleRegistrar registrar(#name, &name::build)

}
