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
#include <string>
#include <vector>

namespace vader
{
class Module; //Forward-declaration

/**
 * @brief This class defines the interface used by modules to retrieve their configuration information
 * 
 * Modules can retrieve any configuration parameter that is specific to that module or that is globally scoped.
 */
class ConfigInterface
{
public:

    ///The key name for the root module (used in the config file)
    static const std::string ROOT_MODULE_KEY;
    ///The key name for the storage module (used in the config file)
    static const std::string STORAGE_MODULE_KEY;
    ///The key name for module children (used in the config file)
    static const std::string VMF_FRAMEWORK_KEY;
    ///The key name for the vmf variables configuration section (used in the config file)
    static const std::string VMF_VARIABLES_KEY;
    ///The key name for the vmf modules configuration section (used in the config file)
    static const std::string VMF_MODULES_KEY;
    ///The key name for the vmf distributed configuration section (used in the config file)
    static const std::string VMF_DISTRIBUTED_KEY;

    /**
     * @brief Get the Output Directory for the application
     * This parameter is handled separately because the top level application creates
     * a dated sub-directory for each vader run.
     * 
     * @return std::string 
     */
    virtual std::string getOutputDir() = 0;

    /**
     * @brief Retrieves the submodules that are associated with this module in the config file(s)
     * 
     * To use, any module can just call getSubModules(getModuleName())
     * Module* will need to be converted to their underlying type, using the convenience methods
     * isAnInstance() and castTo() that are defined in each of the module base classes.
     * 
     * @param parentModuleName the name of the module 
     * @return std::vector<Module*> the submodules
     */
    virtual std::vector<Module*> getSubModules(std::string parentModuleName) = 0;

    /**
     * @brief Check to see if a parameter is defined in a config file, without returning the value.
     * 
     * This method is primarily useful for truly optional parameters.  Parameters with a default
     * value should instead be retrieved with the appropriate getXXXParam method (using the version
     * accepts a default parameter -- e.g. getIntParam(moduleName,paramName,defaultValue).
     * 
     * Both module specific and global parameters may be retrieved with this method.
     * 
     * @param moduleName the name of the module (use getModuleName())
     * @param paramName the name of the parameter, which must match the name that is in the config file
     * @return true if an instance of the parameter is defined, and false otherwise
    */
    virtual bool isParam(std::string moduleName, std::string paramName) = 0;

    /**
     * @brief Get a string of all data from the config associated with the module name.
     * Both module specific and global parameters may be retrieved with this method.
     *
     * @param moduleName the name of the module (use getModuleName())
     * @return std::string the concatenated value of all configs
     */
    virtual std::string getAllParams(std::string moduleName) = 0;

    /**
     * @brief Get a required string based parameter from the config file(s)
     * Both module specific and global parameters may be retrieved with this method
     * 
     * @param moduleName the name of the module (use getModuleName())
     * @param paramName the name of the parameter, which must match the name that is in the config file
     * @return std::string the associated value
     * @throws RuntimeException if the parameter is not found
     */
    virtual std::string getStringParam(std::string moduleName, std::string paramName) = 0;

    /**
     * @brief Get an optional string based parameter from the config file(s)
     * Both module specific and global parameters may be retrieved with this method.
     * If the parameter is not found in the config file, the provided default value will be returned instead.
     * 
     * @param moduleName the name of the module (use getModuleName())
     * @param paramName the name of the parameter, which must match the name that is in the config file
     * @param defaultValue the default value to return if the config option is not in the file
     * @return std::string the associated value
     */
    virtual std::string getStringParam(std::string moduleName, std::string paramName, std::string defaultValue) = 0;

    /**
     * @brief Get a required string vector based parameter from the config file(s)
     * Both module specific and global parameters may be retrieved with this method
     * 
     * @param moduleName the name of the module (use getModuleName())
     * @param paramName the name of the parameter, which must match the name that is in the config file
     * @return std::vector<std::string> the associated value
     * @throws RuntimeException if the parameter is not found
     */
    virtual std::vector<std::string> getStringVectorParam(std::string moduleName, std::string paramName) = 0;

    /**
     * @brief Get an optional string vector based parameter from the config file(s)
     * Both module specific and global parameters may be retrieved with this method
     * 
     * @param moduleName the name of the module (use getModuleName())
     * @param paramName the name of the parameter, which must match the name that is in the config file
     * @param defaultValue the default value to return if the config option is not in the file
     * @return std::vector<std::string> the associated value
     * @throws RuntimeException if the parameter is not found
     */
    virtual std::vector<std::string> getStringVectorParam(std::string moduleName, std::string paramName, std::vector<std::string> defaultValue) = 0;

    /**
     * @brief Get a required integer based parameter from the config file(s)
     * Both module specific and global parameters may be retrieved with this method
     * 
     * @param moduleName the name of the module (use getModuleName())
     * @param paramName the name of the parameter, which must match the name that is in the config file
     * @return int the associated value
     * @throws RuntimeException if the parameter is not found
     */
    virtual int getIntParam(std::string moduleName, std::string paramName) = 0;

    /**
     * @brief Get an optional integer based parameter from the config file(s)
     * Both module specific and global parameters may be retrieved with this method.
     * If the parameter is not found in the config file, the provided default value will be returned instead.
     * 
     * @param moduleName the name of the module (use getModuleName())
     * @param paramName the name of the parameter, which must match the name that is in the config file
     * @param defaultValue the default value to return if the config option is not in the file
     * @return int the associated value
     */
    virtual int getIntParam(std::string moduleName, std::string paramName, int defaultValue) = 0;
    
    /**
     * @brief Get a required int vector based parameter from the config file(s)
     * Both module specific and global parameters may be retrieved with this method
     *
     * @param moduleName the name of the module (use getModuleName())
     * @param paramName the name of the parameter, which must match the name that is in the config file
     * @return std::vector<int> the associated value
     * @throws RuntimeException if the parameter is not found
     */
    virtual std::vector<int> getIntVectorParam(std::string moduleName, std::string paramName) = 0;

    /**
     * @brief Get an optional int vector based parameter from the config file(s)
     * Both module specific and global parameters may be retrieved with this method.
     * If the parameter is not found in the config file, the provided default value will be returned instead.
     *
     * @param moduleName the name of the module (use getModuleName())
     * @param paramName the name of the parameter, which must match the name that is in the config file
     * @param defaultValue the default to return if the parameter is not found
     * @return std::vector<int> the associated value
     * @throws RuntimeException if the parameter is not found
     */
    virtual std::vector<int> getIntVectorParam(std::string moduleName, std::string paramName, std::vector<int> defaultValue) = 0;

    /**
     * @brief Get a required float based parameter from the config file(s)
     * Both module specific and global parameters may be retrieved with this method
     * 
     * @param moduleName the name of the module (use getModuleName())
     * @param paramName the name of the parameter, which must match the name that is in the config file
     * @return float the associated value
     * @throws RuntimeException if the parameter is not found
     */
    virtual float getFloatParam(std::string moduleName, std::string paramName) = 0;

    /**
     * @brief Get an optional float based parameter from the config file(s)
     * Both module specific and global parameters may be retrieved with this method.
     * If the parameter is not found in the config file, the provided default value will be returned instead.
     * 
     * @param moduleName the name of the module (use getModuleName())
     * @param paramName the name of the parameter, which must match the name that is in the config file
     * @param defaultValue the default value to return if the config option is not in the file
     * @return float the associated value
     */
    virtual float getFloatParam(std::string moduleName, std::string paramName, float defaultValue) = 0;
    
    /**
     * @brief Get a required float vector based parameter from the config file(s)
     * Both module specific and global parameters may be retrieved with this method
     *
     * @param moduleName the name of the module (use getModuleName())
     * @param paramName the name of the parameter, which must match the name that is in the config file
     * @return std::vector<float> the associated value
     * @throws RuntimeException if the parameter is not found
     */
    virtual std::vector<float> getFloatVectorParam(std::string moduleName, std::string paramName) = 0;

    /**
     * @brief Get an optional float vector based parameter from the config file(s)
     * Both module specific and global parameters may be retrieved with this method.
     * If the parameter is not found in the config file, the provided default value will be returned instead.
     *
     * @param moduleName the name of the module (use getModuleName())
     * @param paramName the name of the parameter, which must match the name that is in the config file
     * @param defaultValue the default to return if the parameter is not found
     * @return std::vector<float> the associated value
     * @throws RuntimeException if the parameter is not found
     */
    virtual std::vector<float> getFloatVectorParam(std::string moduleName, std::string paramName, std::vector<float> defaultValue) = 0;

    /**
     * @brief Get a required boolean based parameter from the config file(s)
     * Both module specific and global parameters may be retrieved with this method.
     * Note: "true" or "TRUE" are acceptable formats for the parameter
     * 
     * @param moduleName the name of the module (use getModuleName())
     * @param paramName the name of the parameter, which must match the name that is in the config file
     * @return bool the associated value
     * @throws RuntimeException if the parameter is not found
     */
    virtual bool getBoolParam(std::string moduleName, std::string paramName) = 0;

    /**
     * @brief Get an optional boolean based parameter from the config file(s)
     * Both module specific and global parameters may be retrieved with this method.
     * If the parameter is not found in the config file, the provided default value will be returned instead.
     * Note: "true" or "TRUE" are acceptable formats for the parameter
     * 
     * @param moduleName the name of the module (use getModuleName())
     * @param paramName the name of the parameter, which must match the name that is in the config file
     * @param defaultValue the default value to return if the config option is not in the file
     * @return bool the associated value
     */
    virtual bool getBoolParam(std::string moduleName, std::string paramName, bool defaultValue) = 0;

    //Note: The above methods are provided individually by type, because C++ does not allow virtual templated functions
};
}
