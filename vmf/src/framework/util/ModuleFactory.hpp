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
#include <map>

namespace vmf
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

    ///Returns a string containing the module instance name given an ID
    std::string getModuleName(int id);

    void registerModule(std::string className, TModuleBuildMethod buildFunc);
    Module* buildModule(std::string className, std::string name);

    // Returns a reference to the singleton instance of ModuleFactory
    static ModuleFactory &getInstance();

    ~ModuleFactory();

protected:
    ///A map of class names to builder methods
    std::map<std::string, TModuleBuildMethod> factoryMap;
    ///A map of unique integer identifiers to module instancenames
    std::map<int, std::string> idMap;

private:
    ///A monotonically incrementing integer to create unique IDs
    int next_id = 0;
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
