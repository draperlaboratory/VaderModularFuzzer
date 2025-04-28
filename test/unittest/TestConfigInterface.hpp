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
#include "ConfigInterface.hpp"
#include <vector>
#include "yaml-cpp/yaml.h"

namespace vmf
{
/**
 * @brief ConfigInterface implementation to support unit testing
 *
 */
class TestConfigInterface : public ConfigInterface
{
public:
    TestConfigInterface();
    virtual ~TestConfigInterface();
    void setOutputDir(std::string dir);
    void addSubmodule(std::string moduleName, Module* module);
    void setIntParam(std::string moduleName, std::string paramName, int value);
    void setIntVectorParam(std::string moduleName, std::string paramName, std::vector<int> value);
    void setStringParam(std::string moduleName, std::string paramName, std::string value);
    void setStringVectorParam(std::string moduleName, std::string paramName, std::vector<std::string> value);
    void setFloatParam(std::string moduleName, std::string paramName, float value);
    void setFloatVectorParam(std::string moduleName, std::string paramName, std::vector<float> value);
    void setBoolParam(std::string moduleName, std::string paramName, bool value);

    virtual std::string getModuleName(int id);

    //Methods required by ConfigInterface -- these are just stubbed out to compile
    virtual std::string getAllParams(std::string moduleName) {return "Method not implemented";}

    //Methods required by ConfigInterface -- these are just stubbed out to compile
    virtual std::string getAllParamsYAML(std::string moduleName);

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

    void dump() {
        std::cerr << _configRoot;
    }
    
private:
    template<typename T> T getParam(std::string moduleName, std::string paramName );
    template<typename T> T getParam(std::string moduleName, std::string paramName, T defaultValue );
    template<typename T> void setParam(std::string moduleName, std::string paramName, T value );

    std::string outputDir = "";
    std::vector<std::pair<std::string, std::vector<Module*>>> submodules;
    YAML::Node _configRoot;
};
}
