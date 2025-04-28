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
#include "TestConfigInterface.hpp"
#include "RuntimeException.hpp"
#include <algorithm>
#include <iostream>

using namespace vmf;

#define GTEST_ERR std::cerr << "[          ] [ ERROR ]"

TestConfigInterface::TestConfigInterface()
{
    //do nothing
}

TestConfigInterface::~TestConfigInterface()
{
    //do nothing
}

std::string TestConfigInterface::getModuleName(int id)
{
    return "Method not implemented";
}

//see ConfigInterface::getAllParamsYAML
std::string TestConfigInterface::getAllParamsYAML(std::string moduleName)
{
    const YAML::Node& node = _configRoot[moduleName];

    if (node)
    {
        std::stringstream SS;
        SS << node; 
        return SS.str();
    }
    return "";
}

bool TestConfigInterface::isParam(std::string moduleName, std::string paramName)
{
    const YAML::Node& node = _configRoot[moduleName];
    return static_cast<bool>(node) && static_cast<bool>(node[paramName]);
}

void TestConfigInterface::setIntParam(std::string moduleName, std::string paramName, int value) 
{ 
    setParam( moduleName, paramName, value ); 
}

void TestConfigInterface::setIntVectorParam(std::string moduleName, std::string paramName, std::vector<int> value) 
{ 
    setParam( moduleName, paramName, value ); 
}

void TestConfigInterface::setStringParam(std::string moduleName, std::string paramName, std::string value) 
{ 
    setParam( moduleName, paramName, value ); 
}

void TestConfigInterface::setStringVectorParam(std::string moduleName, std::string paramName, std::vector<std::string> value) 
{ 
    setParam( moduleName, paramName, value ); 
}

void TestConfigInterface::setFloatParam(std::string moduleName, std::string paramName, float value) 
{ 
    setParam( moduleName, paramName, value ); 
}

void TestConfigInterface::setFloatVectorParam(std::string moduleName, std::string paramName, std::vector<float> value) 
{ 
    setParam( moduleName, paramName, value ); 
}

void TestConfigInterface::setBoolParam(std::string moduleName, std::string paramName, bool value) 
{ 
    setParam( moduleName, paramName, value ); 
}

//see ConfigInterface::getStringParam
std::string TestConfigInterface::getStringParam(std::string moduleName, std::string paramName)
{
    return getParam<std::string>(moduleName, paramName);
}

//see ConfigInterface::getStringParam
std::string TestConfigInterface::getStringParam(std::string moduleName, std::string paramName, std::string defaultValue)
{
    return getParam<std::string>(moduleName, paramName, defaultValue);
}

//see ConfigInterface::getStringVectorParam
std::vector<std::string> TestConfigInterface::getStringVectorParam(std::string moduleName, std::string paramName)
{
    return getParam<std::vector<std::string>>(moduleName, paramName);
}

//see ConfigInterface::getStringVectorParam
std::vector<std::string> TestConfigInterface::getStringVectorParam(std::string moduleName, std::string paramName, std::vector<std::string> defaultValue)
{
    return getParam<std::vector<std::string>>(moduleName, paramName, defaultValue);
}

//see ConfigInterface::getIntParam
int TestConfigInterface::getIntParam(std::string moduleName, std::string paramName)
{
    return getParam<int>(moduleName, paramName);
}

//see ConfigInterface::getIntParam
int TestConfigInterface::getIntParam(std::string moduleName, std::string paramName, int defaultValue)
{
    return getParam<int>(moduleName, paramName, defaultValue);
}

//see ConfigInterface::getIntVectorParam
std::vector<int> TestConfigInterface::getIntVectorParam(std::string moduleName, std::string paramName)
{
    return getParam<std::vector<int>>(moduleName, paramName);
}

//see ConfigInterface::getIntVectorParam
std::vector<int> TestConfigInterface::getIntVectorParam(std::string moduleName, std::string paramName, std::vector<int> defaultValue)
{
    return getParam<std::vector<int>>(moduleName, paramName, defaultValue);
}

//see ConfigInterface::getFloatParam
float TestConfigInterface::getFloatParam(std::string moduleName, std::string paramName)
{
    return getParam<float>(moduleName, paramName);
}

//see ConfigInterface::getFloatParam
float TestConfigInterface::getFloatParam(std::string moduleName, std::string paramName, float defaultValue)
{
    return getParam<float>(moduleName, paramName, defaultValue);
}

//see ConfigInterface::getFloatVectorParam
std::vector<float> TestConfigInterface::getFloatVectorParam(std::string moduleName, std::string paramName)
{
    return getParam<std::vector<float>>(moduleName, paramName);
}

//see ConfigInterface::getFloatVectorParam
std::vector<float> TestConfigInterface::getFloatVectorParam(std::string moduleName, std::string paramName, std::vector<float> defaultValue)
{
    return getParam<std::vector<float>>(moduleName, paramName, defaultValue);
}

//see ConfigInterface::getBoolParam
bool TestConfigInterface::getBoolParam(std::string moduleName, std::string paramName)
{
    bool option = getParam<bool>(moduleName, paramName);
    return option;
}

//see ConfigInterface::getBoolParam
bool TestConfigInterface::getBoolParam(std::string moduleName, std::string paramName, bool defaultValue)
{
    bool option = getParam<bool>(moduleName, paramName, defaultValue);
    return option;
}

void TestConfigInterface::setOutputDir(std::string dir)
{
    outputDir = dir;
}

std::string TestConfigInterface::getOutputDir()
{
    return outputDir;
}

void TestConfigInterface::addSubmodule(std::string moduleName, Module* module)
{
    bool found = false;
    //Look for the index into the submodules data structure
    //This structure maps a module name to a list of submodules
    for(int i=0; i< submodules.size(); i++)
    {
        if(moduleName == submodules[i].first)
        {
            //We found the entry, go ahead add the module
            found = true;
            submodules[i].second.push_back(module);
        }
    }

    if(!found)
    {
        //This is a new submodule name, we need to add it to the data structure
        std::vector<Module*> newModuleList;
        newModuleList.push_back(module);
        submodules.push_back(std::make_pair(moduleName, newModuleList));
    }

}

std::vector<Module*> TestConfigInterface::getSubModules(std::string parentModuleName)
{
    for(int i=0; i< submodules.size(); i++)
    {
        if(parentModuleName == submodules[i].first)
        {
            return submodules[i].second;
        }
    }

    //Otherwise, there are no submodules, return an empty list
    return {};
}

/**
 * @brief Helper method to find a required cofiguration parameter
 * This templated method is used as the implemenation for all of the getXXXConfig
 * methods required by ConfigInterface.
 * 
 * @tparam T the type to retrieve
 * @param moduleName the name of the module requesting the configuration parameter
 * @param paramName the name of the parameter (must match the config file)
 * @return T the configuration value
 * @throws RuntimeExcepttion if the parameter is not found
 */
template<typename T> T TestConfigInterface::getParam(std::string moduleName, std::string paramName)
{
    const YAML::Node& node = _configRoot[moduleName];

    if(node && node[paramName])
    {
        return node[paramName].as<T>();
    }
    else
    {
        throw RuntimeException("getParam failed because the param value was not yet set");
    }
}

/**
 * @brief Helper method to find a required cofiguration parameter
 * This templated method is used as the implemenation for all of the getXXXConfig
 * methods required by ConfigInterface.
 * 
 * @tparam T the type to retrieve
 * @param moduleName the name of the module requesting the configuration parameter
 * @param paramName the name of the parameter (must match the config file)
 * @param defValue the default value if the parameter is not defined in config
 * @return T the configuration value
 * @throws RuntimeExcepttion if the parameter is not found
 */
template<typename T> T TestConfigInterface::getParam(std::string moduleName, std::string paramName, T defValue)
{
    const YAML::Node& node = _configRoot[moduleName];

    if(node && node[paramName])
    {
        return node[paramName].as<T>();
    }
    else
    {
        return defValue;
    }
}

/**
 * @brief Helper method to set a required cofiguration parameter
 * This templated method is used as the implemenation for all of the setXXXConfig
 * methods required by ConfigInterface.
 * 
 * @tparam T the type to retrieve
 * @param moduleName the name of the module requesting the configuration parameter
 * @param paramName the name of the parameter (must match the config file)
 * @return T the configuration value
 * @throws RuntimeExcepttion if the parameter is not found
 */
template<typename T> void TestConfigInterface::setParam(std::string moduleName, std::string paramName, T value )
{
    _configRoot[moduleName][paramName] = value;
}
