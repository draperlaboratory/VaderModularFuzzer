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
#include "ModuleManager.hpp"
#include "StorageModule.hpp"
#include "yaml-cpp/yaml.h"
#include <vector>

namespace vmf
{
/**
 * @brief Responsible for loading modules and parameters from the configuration file
 * This class parses the configuration file and provides methods to create and intialize
 * the modules in the configuration file, as well as methods for modules to retrieve
 * their own configuration parameters.
 *
 */
class ConfigManager : public ConfigInterface
{
public:

    ConfigManager(std::vector<std::string> filenames, ModuleManager* manager);
    virtual ~ConfigManager();

    void readConfig();
    void readConfig(std::vector<std::string> filenames);
    void addConfig(std::string cfg);
    void parseConfig();
    void reloadConfig();
    void writeConfig(std::string outputFilePath);
    void loadModules();

    virtual std::string getOutputDir();
    virtual void setOutputDir(std::string dir);
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
    
    virtual std::string getAllParams(std::string moduleName);
private:
    std::vector<std::string> buildChildren(YAML::Node topLevelNode);
    void buildModuleIfNotExist(std::string classNameString, std::string idString);
    YAML::Node findRequiredConfig(std::string name);
    YAML::Node findConfig(std::string name);
    YAML::Node findConfigParam(std::string moduleName, std::string paramName);
    template<typename T> T getParam(std::string moduleName, std::string paramName);
    template<typename T> T getParam(std::string moduleName, std::string paramName, T defaultValue);
    std::string getNodeAsString(const YAML::Node& node);

    std::vector<std::string> filenames;
    std::string theConfigAsString;
    YAML::Node theConfig;
    std::string outputDir;
    int configCount;

    std::string initialConfigBackup;
    ModuleManager* moduleManager;
};
}
