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
#include "ConfigInterface.hpp"
#include <vector>

namespace vmf
{
/**
 * @brief ConfigInterface implementation to support unit testing
 * Note: In this implementation, the moduleName is ignored completely, so paramNames will
 * need to be unique within the data type (e.g. no more than one param named "x" of type int).
 * For the isParam() method to work correctly, all params must have unique names across datatypes.
 */
class TestConfigInterface : public ConfigInterface
{
public:
    TestConfigInterface();
    virtual ~TestConfigInterface();
    void setOutputDir(std::string dir);
    void addSubmodule(Module* module);
    void setIntParam(std::string paramName, int value);
    void setIntVectorParam(std::string paramName, std::vector<int> value);
    void setStringParam(std::string paramName, std::string value);
    void setStringVectorParam(std::string paramName, std::vector<std::string> value);
    void setFloatParam(std::string paramName, float value);
    void setFloatVectorParam(std::string paramName, std::vector<float> value);
    void setBoolParam(std::string paramName, bool value);

    //Methods required by ConfigInterface -- these are just stubbed out to compile
    virtual std::string getAllParams(std::string moduleName) {return "Method not implemented";}

    //Methods required by ConfigInterface -- these have reasonably real implementations
    virtual std::string getOutputDir();
    virtual std::vector<Module*> getSubModules(std::string parentModuleName);
    virtual bool isParam(std::string moduleName, std::string paramName);
    virtual std::string getStringParam(std::string moduleName, std::string paramName);
    virtual std::string getStringParam(std::string moduleName, std::string paramName, std::string defaultValue);
    virtual std::vector<std::string> getStringVectorParam(std::string moduleName, std::string paramName);
    virtual std::vector<std::string> getStringVectorParam(std::string moduleName, std::string paramName, std::vector<std::string> defaultValue);
    virtual int getIntParam(std::string moduleName, std::string paramName);
    virtual int getIntParam(std::string moduleName, std::string paramName, int defaultValue);
    virtual std::vector<int> getIntVectorParam(std::string moduleName, std::string paramName);
    virtual std::vector<int> getIntVectorParam(std::string moduleName, std::string paramName, std::vector<int> defaultValue);
    virtual float getFloatParam(std::string moduleName, std::string paramName);
    virtual float getFloatParam(std::string moduleName, std::string paramName, float defaultValue);
    virtual std::vector<float> getFloatVectorParam(std::string moduleName, std::string paramName);
    virtual std::vector<float> getFloatVectorParam(std::string moduleName, std::string paramName, std::vector<float> defaultValue);
    virtual bool getBoolParam(std::string moduleName, std::string paramName);
    virtual bool getBoolParam(std::string moduleName, std::string paramName, bool defaultValue);

private:
    int containsName(std::string name, std::vector<std::string>& nameList);
    template<typename T> T getParam(std::string paramName, std::vector<std::string>& nameList, std::vector<T>& valueList);
    template<typename T> T getParam(std::string paramName, T defaultValue, std::vector<std::string>& nameList, std::vector<T>& valueList);
    template<typename T> void setParam(std::string paramName, T value, std::vector<std::string>& nameList, std::vector<T>& valueList);

    std::string outputDir = "";
    std::vector<Module*> submodules;

    std::vector<std::string> intParamNames;
    std::vector<int> intParamValues;

    std::vector<std::string> intVectorParamNames;
    std::vector<std::vector<int>> intVectorParamValues;

    std::vector<std::string> stringParamNames;
    std::vector<std::string> stringParamValues;

    std::vector<std::string> stringVectorParamNames;
    std::vector<std::vector<std::string>> stringVectorParamValues;

    std::vector<std::string> floatParamNames;
    std::vector<float> floatParamValues;

    std::vector<std::string> floatVectorParamNames;
    std::vector<std::vector<float>> floatVectorParamValues;

    std::vector<std::string> boolParamNames;
    std::vector<bool> boolParamValues;

};
}