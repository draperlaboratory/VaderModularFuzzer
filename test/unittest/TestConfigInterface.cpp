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
#include "TestConfigInterface.hpp"
#include "RuntimeException.hpp"
#include <algorithm>

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

/**
 * @brief Helper method to see if this parameter has been added before
 * If it has, return the index to the parameter, if it has not, return -1
 * 
 * @param name the name to look for
 * @param nameList the list of names to check 
 * @return int the index, or -1 if not found
 */
int TestConfigInterface::containsName(std::string name, std::vector<std::string>& nameList)
{
    int index = -1;
    std::vector<std::string>::iterator it = std::find(nameList.begin(), nameList.end(), name);
    if(it != nameList.end())
    {
        //name was found
        index = it - nameList.begin();
    }
    return index;
}

template<typename T> T TestConfigInterface::getParam(std::string paramName, std::vector<std::string>& nameList, std::vector<T>& valueList)
{
    int index = containsName(paramName,nameList);
    if(-1 == index)
    {
        GTEST_ERR << "Param not set: " << paramName << "\n";
        throw RuntimeException("getParam failed because the param value was not yet set");
    }
    else
    {
        return valueList[index];
    }
}

template<typename T> T TestConfigInterface::getParam(std::string paramName, T defaultValue, std::vector<std::string>& nameList, std::vector<T>& valueList)
{
    int index = containsName(paramName,nameList);
    if(-1 == index)
    {
        return defaultValue;
    }
    else
    {
        return valueList[index];
    }
}

template<typename T> void TestConfigInterface::setParam(std::string paramName, T value, std::vector<std::string>& nameList, std::vector<T>& valueList)
{
    int index = containsName(paramName,nameList);
    if(-1 == index)
    {
        nameList.push_back(paramName);
        valueList.push_back(value);
    }
    else
    {
        valueList[index] = value;
    }
}

bool TestConfigInterface::isParam(std::string moduleName, std::string paramName)
{
    if(-1 != containsName(paramName, intParamNames))
    {
        return true;
    }
    if(-1 != containsName(paramName, stringParamNames))
    {
        return true;
    }
    if(-1 != containsName(paramName, floatParamNames))
    {
        return true;
    }
    if(-1 != containsName(paramName, boolParamNames))
    {
        return true;
    }
    if(-1 != containsName(paramName, intVectorParamNames))
    {
        return true;
    }
    if(-1 != containsName(paramName, stringVectorParamNames))
    {
        return true;
    }
    if(-1 != containsName(paramName, floatVectorParamNames))
    {
        return true;
    }
    return false;
}

void TestConfigInterface::setOutputDir(std::string dir)
{
    outputDir = dir;
}

std::string TestConfigInterface::getOutputDir()
{
    return outputDir;
}

void TestConfigInterface::addSubmodule(Module* module)
{
    submodules.push_back(module);
}

std::vector<Module*> TestConfigInterface::getSubModules(std::string parentModuleName)
{
    return submodules;
}

void TestConfigInterface::setIntParam(std::string paramName, int value)
{
    setParam(paramName,value,intParamNames,intParamValues);
}

int TestConfigInterface::getIntParam(std::string moduleName, std::string paramName)
{
    return getParam(paramName,intParamNames,intParamValues);
}

int TestConfigInterface::getIntParam(std::string moduleName, std::string paramName, int defaultValue)
{
    return getParam(paramName,defaultValue,intParamNames,intParamValues);
}

void TestConfigInterface::setStringParam(std::string paramName, std::string value)
{
    setParam(paramName,value,stringParamNames,stringParamValues);
}

std::string TestConfigInterface::getStringParam(std::string moduleName, std::string paramName)
{
    return getParam(paramName,stringParamNames,stringParamValues);
}

std::string TestConfigInterface::getStringParam(std::string moduleName, std::string paramName, std::string defaultValue)
{
    return getParam(paramName,defaultValue,stringParamNames,stringParamValues);
}

void TestConfigInterface::setStringVectorParam(std::string paramName, std::vector<std::string> value)
{
    setParam(paramName,value,stringVectorParamNames,stringVectorParamValues);
}

std::vector<std::string> TestConfigInterface::getStringVectorParam(std::string moduleName, std::string paramName)
{
    return getParam(paramName,stringVectorParamNames,stringVectorParamValues);
}

std::vector<std::string> TestConfigInterface::getStringVectorParam(std::string moduleName, std::string paramName, std::vector<std::string> defaultValue)
{
    return getParam(paramName,defaultValue,stringVectorParamNames,stringVectorParamValues);
}

void TestConfigInterface::setIntVectorParam(std::string paramName, std::vector<int> value)
{
    setParam(paramName,value,intVectorParamNames,intVectorParamValues);
}

std::vector<int> TestConfigInterface::getIntVectorParam(std::string moduleName, std::string paramName)
{
    return getParam(paramName,intVectorParamNames,intVectorParamValues);
}
std::vector<int> TestConfigInterface::getIntVectorParam(std::string moduleName, std::string paramName, std::vector<int> defaultValue)
{
    return getParam(paramName,defaultValue,intVectorParamNames,intVectorParamValues);
}

void TestConfigInterface::setFloatParam(std::string paramName, float value)
{
    setParam(paramName,value,floatParamNames,floatParamValues);
}

float TestConfigInterface::getFloatParam(std::string moduleName, std::string paramName)
{
    return getParam(paramName,floatParamNames,floatParamValues);
}

float TestConfigInterface::getFloatParam(std::string moduleName, std::string paramName, float defaultValue)
{
    return getParam(paramName,defaultValue,floatParamNames,floatParamValues);
}

void TestConfigInterface::setFloatVectorParam(std::string paramName, std::vector<float> value)
{
    setParam(paramName,value,floatVectorParamNames,floatVectorParamValues);
}

std::vector<float> TestConfigInterface::getFloatVectorParam(std::string moduleName, std::string paramName)
{
    return getParam(paramName,floatVectorParamNames,floatVectorParamValues);
}

std::vector<float> TestConfigInterface::getFloatVectorParam(std::string moduleName, std::string paramName, std::vector<float> defaultValue)
{
    return getParam(paramName,defaultValue,floatVectorParamNames,floatVectorParamValues);
}

void TestConfigInterface::setBoolParam(std::string paramName, bool value)
{
    setParam(paramName,value,boolParamNames,boolParamValues);
}

bool TestConfigInterface::getBoolParam(std::string moduleName, std::string paramName)
{
    return getParam(paramName,boolParamNames,boolParamValues);
}

bool TestConfigInterface::getBoolParam(std::string moduleName, std::string paramName, bool defaultValue)
{
    return getParam(paramName,defaultValue,boolParamNames,boolParamValues);
}
    