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
#include "ConfigManager.hpp"
#include "RuntimeException.hpp"
#include "Logging.hpp"
#include "StorageUserModule.hpp"
#include <map>
#include <vector>
#include <iostream>
#include <fstream>
#include <filesystem>

using namespace vmf;

/**
 * @brief Construct a new Config Manager object
 * Note that the configuration files are not read until loadModules() is called.
 * 
 * @param filenames the list of configuration filenames to read
 * @param manager the module manager for this application
 */
ConfigManager::ConfigManager(std::vector<std::string> filenames, ModuleManager* manager) 
{
    this->filenames = filenames;
    this->configCount = 0;
    this->moduleManager = manager;
}

/**
 * @brief Destroy the Config Manager object
 * 
 */
ConfigManager::~ConfigManager()
{
    
}


/**
 * @brief Parses the passed configuration files
 *
 * @throws RuntimeException if there are any errors parsing the config files
 */
void ConfigManager::readConfig(std::vector<std::string> filenames)
{
    this->filenames = filenames;

    readConfig();
}

/** 
 * Helper method to add the provided configuration string to the current config (theConfigAsString).
 * First we determine if this particular config string should be prepended (rather than appended),
 * based on looking for the VMF_VARIABLES_KEY or VMF_CLASS_SET_KEY.
 * @param newConfig the new config to add
*/
void ConfigManager::addToConfig(std::string newConfig)
{
    //We need to make sure that the key is present, and not within a commented out line
    bool shouldPrepend = false;
    std::istringstream configStream(newConfig);
    std::string line;    
    while (std::getline(configStream, line)) {
        //Check for VMF_VARIABLES_KEY
        const auto varKeyPos = line.find(VMF_VARIABLES_KEY);
        if(std::string::npos != varKeyPos)
        {
            //Make sure this key didn't appear after a comment character
            const auto commentPos = line.find("#");
            if((std::string::npos == commentPos)||(commentPos > varKeyPos))
            {
                //This is real, non-commented out key, this file should be pre-pended
                shouldPrepend = true;
                break; //No need to keep searching
            }
        }

        //Check for VMF_CLASS_SET_KEY
        const auto classKeyPos = line.find(VMF_CLASS_SET_KEY);
        if(std::string::npos != classKeyPos)
        {
            //Make sure this key didn't appear after a comment character
            const auto commentPos = line.find("#");
            if((std::string::npos == commentPos)||(commentPos > classKeyPos))
            {
                //This is real, non-commented out key, this file should be pre-pended
                shouldPrepend = true;
                break; //No need to keep searching
            }
        }
    }

    if (shouldPrepend)
    {
        // pre-pend this yaml config
        theConfigAsString.insert(0, newConfig + "\n");
    }
    else
    {
        // append this yaml config
        theConfigAsString += "\n";
        theConfigAsString.append(newConfig);
    }
}

/**
 * @brief Parses the configuration files stored as a member variable
 *
 * @throws RuntimeException if there are any errors parsing the config files
 */
void ConfigManager::readConfig()
{
    std::ifstream inFile;

    for (std::string file : filenames) 
    {
        inFile.open(file);
        if (inFile.is_open()) 
        {
            // get size of file contents and create string of same length
            inFile.seekg(0, inFile.end);
            int size = (int) inFile.tellg();
            std::string thisInput(size,' ');

            // read file contents into string
            inFile.seekg(0, inFile.beg);
            inFile.read(&thisInput[0], size);

            addToConfig(thisInput);

        } 
        else 
        {
            // logger not initialized yet at this point
            LOG_FATAL << "Unable to open input file: " << file << "\n" << std::flush;
            throw RuntimeException("Unable to open input file", RuntimeException::CONFIGURATION_ERROR);
        }
        inFile.close();
    }

    // parse string of all inputs
    initialConfigBackup = theConfigAsString;
    try
    {
        theConfig = YAML::Load(theConfigAsString);
    }
    catch(const YAML::ParserException& e)
    {
        // Log exception info
        LOG_FATAL << "Parse exception in " << e.what();

        // Log offending line
        int lineNum = e.mark.line;
        std::istringstream iStringConfig(theConfigAsString);
        std::string line;

        for (int i = 0; i < lineNum + 1; i++)
        {
            std::getline(iStringConfig, line);
        }

        LOG_FATAL << "Referenced line: "  << line;

        // Dump existing config for user as file
        char dump_filename[] = "config_dump.yaml";
        LOG_FATAL << "Writing a copy of aggregated config to " << std::filesystem::current_path() / (dump_filename);
        std::ofstream fout(dump_filename);
        fout << theConfigAsString;
        fout.close();

        throw RuntimeException("Error parsing YAML config file", RuntimeException::CONFIGURATION_ERROR);
    }
    catch(const std::exception& e)
    {
        LOG_FATAL << "Parsing Exception:" << e.what() << '\n';
        throw RuntimeException("Error parsing YAML config file", RuntimeException::CONFIGURATION_ERROR);
    }

}

/**
 * @brief Adds additional yaml configuration information to the config manager
 * This must be followed by a call to parseConfig() once all the new configuration
 * data has been read in.
 * 
 * @param cfg the yaml to add
 */
void ConfigManager::addConfig(std::string cfg)
{
    addToConfig(cfg);
}

/**
 * @brief Parses the currently loaded configuration information
 * This method should be called after addConfig in order to reparse the loaded
 * information.
 * @throws RuntimeException if there are any parsing errors
 */
void ConfigManager::parseConfig()
{
    theConfig.reset();
    
    try
    {
        theConfig = YAML::Load(theConfigAsString);
    }
    catch(const std::exception& e)
    {
        LOG_ERROR << "YAML Parsing error;" << e.what();
        throw RuntimeException("Error parsing YAML config file", RuntimeException::CONFIGURATION_ERROR);
    }
}

/**
 * @brief Clear config and then restore the initial set of configuration data
 * This does not effect the currently loaded modules.  The initial config files
 * are not re-read, rather a cached copy of the data is used.
 */
void ConfigManager::reloadConfig()
{
    theConfigAsString = initialConfigBackup;
    theConfig.reset();
    YAML::Load(theConfigAsString);
}

/**
 * @brief Records the consolidated input configs to the output directory
 * The first call to this method will output to config.yaml.  Subsequent
 * calls will add a number to the filename (e.g. config2.yaml).
 * 
 * @param outputFilePath the filepath of the output directory
 */
void ConfigManager::writeConfig(std::string outputFilePath)
{
    // create file in output directory 
    std::string filename = outputFilePath;
    configCount++;
    if(1 == configCount)
    {
        filename += "/config.yaml";
    }
    else
    {
        filename += "/config" + std::to_string(configCount) + ".yaml";
    }


    std::ofstream fout(filename);
    fout << theConfig;
}

/**
 * @brief Instantiates the modules from the config file
 *
 * @throws RuntimeException if there are any errors in construction the modules
 */
void ConfigManager::loadModules()
{
    YAML::Node modules = findRequiredConfig(VMF_MODULES_KEY);

    if(modules.Type() == YAML::NodeType::Map)
    {
        //Build storage module
        YAML::Node storage = modules[STORAGE_MODULE_KEY];
        if(storage)
        {
            YAML::Node className = storage["className"];
            YAML::Node id = storage["id"];
            std::string classNameString = className.as<std::string>();
            std::string idString = classNameString; //id string will default to the className
            if(id)
            {
                idString = id.as<std::string>();
            }
            if(className)
            {
                Module* sm = moduleManager->buildModule(classNameString, idString);
                moduleManager->setStorageModule(sm);
            }
        }

        //Build controller module
        YAML::Node root = modules[ROOT_MODULE_KEY];
        if(root)
        {
            YAML::Node className = root["className"];
            YAML::Node id = root["id"];
            std::string classNameString = className.as<std::string>();
            std::string idString = classNameString; //id string will default to the className
            if(id)
            {
                idString = id.as<std::string>();
            }
            if(className)
            {
                Module* rm = moduleManager->buildModule(classNameString, idString);
                moduleManager->setRootModule(rm);
            }
            
            // Build controller children
            std::vector<std::string> childNodes = buildChildren(root);

            // Build up to 9 more generations of children
            for(size_t curr_depth = 0; curr_depth < 10; curr_depth++)
            {
                std::vector<std::string> nextGenOfChildren;

                for(std::string childName: childNodes)
                {
                    // Does this child have further submodules described in the yaml configuration?
                    YAML::Node child = modules[childName];
                    if(child)
                    {
                        // Build it's children and save the list of those built in case they have children
                        std::vector<std::string> newChildren = buildChildren(child);

                        // Append new children to next gen list
                        nextGenOfChildren.insert(nextGenOfChildren.end(), newChildren.begin(), newChildren.end());                        
                    }
                }
                
                // Move next generation list over child nodes to prepare building next generation
                childNodes = std::move(nextGenOfChildren);
            }
        }
    }
    else
    {
        throw RuntimeException("Unable to parse list of modules from config file",
                  RuntimeException::CONFIGURATION_ERROR);
    }

}

/**
 * @brief Helper method to build any child classes under this node name
 * Looks for "children", and if present, builds any child nodes listed
 * 
 * @param topLevelNode the node to look at
 * @returns the list children that were created (by id, if there is one, otherwise by className)
 */
std::vector<std::string> ConfigManager::buildChildren(YAML::Node topLevelNode)
{
    std::vector<std::string> childList;
    YAML::Node children = topLevelNode["children"];
    if((children) && (children.Type() == YAML::NodeType::Sequence))
    {
        for(size_t i=0; i<children.size(); i++)
        {
            //First check to see if this is a classSet
            YAML::Node classSet = children[i]["classSet"];
            if(classSet)
            {
                //Build each module in the class set (ids are not supported with this syntax)
                if(classSet.Type() == YAML::NodeType::Sequence){
                    for(size_t j=0; j<classSet.size(); j++)
                    {
                        YAML::Node className = classSet[j];
                        std::string classNameString = className.as<std::string>();
                        //Build the module if it doesn't already exist
                        buildModuleIfNotExist(classNameString, classNameString);
                        childList.push_back(classNameString);
                    }
                }
                else
                {
                    LOG_ERROR << "ClassSet node not of expected type";
                }
            }
            else //This is a single module, just build it
            {
                //Load the className and optional id for each module
                YAML::Node id = children[i]["id"];
                YAML::Node className = children[i]["className"];
                std::string classNameString = className.as<std::string>();
                std::string idString = classNameString; //id string will default to the className
                if(id)
                {
                    idString = id.as<std::string>();
                }
            
                //Build the module if it doesn't already exist
                buildModuleIfNotExist(classNameString, idString);
                childList.push_back(idString);
            }
        }
    }

    return childList;
}

/**
 * @brief Helper method to build a module if it doesn't already exist
 * 
 * @param classNameString the class name of the module
 * @param idString the unique module name to use for the module (this can be the same as the class name)
 */
void ConfigManager::buildModuleIfNotExist(std::string classNameString, std::string idString)
{
    if(!(moduleManager->containsModule(idString)))
    {
        moduleManager->buildModule(classNameString, idString);
    }
}


//See ConfigInterface.hpp
std::string ConfigManager::getOutputDir()
{
    return outputDir;
}

/**
 * @brief Set the Output Directory
 * 
 * @param dir 
 */
void ConfigManager::setOutputDir(std::string dir)
{
    outputDir = dir;
}

/**
 * @brief Returns a string representation of a node
 *
 * @return std::string Single line representation of a node and its children
 */
std::string ConfigManager::getNodeAsYAML(const YAML::Node& node)
{
    std::stringstream SS;
    SS << node; 
    return SS.str();
}

/**
 * @brief Returns a string representation of a node
 *
 * @return std::string Single line representation of a node and its children
 */
std::string ConfigManager::getNodeAsString(const YAML::Node& node)
{
    // Return value
    std::string nodeString = "";
    // First pass at sequence
    bool sequencefirstPass = true;

    switch (node.Type())
    {
    case YAML::NodeType::Null:
        nodeString = "Null";
        break;
    case YAML::NodeType::Scalar:
        nodeString = node.as<std::string>();
        break;
    case YAML::NodeType::Sequence:
        nodeString += "[";
        for (YAML::const_iterator seq_it = node.begin(); seq_it != node.end(); ++seq_it)
        {
            if (sequencefirstPass)
            {
                sequencefirstPass = false;
            }
            else
            {
                nodeString += ", ";
            }
            nodeString += getNodeAsString(*seq_it);
        }
        nodeString += "]";
        break;
    case YAML::NodeType::Map:
        nodeString += "{";
        for(YAML::const_iterator it = node.begin();it != node.end(); ++it) {
            nodeString += getNodeAsString(it->first) + " : " + getNodeAsString(it->second);
        }
        nodeString += "}";
        break;
    case YAML::NodeType::Undefined:
        nodeString += "Undefined node";
        break;
    default:
        nodeString += "YAML::Node produced unexpected type";
        break;
    }

    return nodeString;
}

//see ConfigInterface::getSubModules
std::vector<Module*> ConfigManager::getSubModules(std::string parentModuleName)
{
    bool found = false;
    std::vector<Module*> list;
    YAML::Node modulesSection = findRequiredConfig(VMF_MODULES_KEY);

    //Child modules are listed under the module name, except for the top level controller
    //and the storage module, whose children are listed under special names.
    std::string lookupName = parentModuleName;
    if(moduleManager->getRootModule()->getModuleName() == parentModuleName)
    {
        lookupName = ROOT_MODULE_KEY;
    }
    else if(moduleManager->getStorageModule()->getModuleName() == parentModuleName)
    {
        lookupName = STORAGE_MODULE_KEY;
    }

    YAML::Node submodulesSection = modulesSection[lookupName];
    if(submodulesSection)
    {
        YAML::Node submodules = submodulesSection["children"];
        if(submodules.Type() == YAML::NodeType::Sequence)
        {
            for(size_t i=0; i<submodules.size(); i++)
            {
                found = true;
                //Look up the module by id, if one is listed, or by className otherwise
                YAML::Node id = submodules[i]["id"];
                YAML::Node className = submodules[i]["className"];
                if(id)
                {
                    list.push_back(moduleManager->getModule(id.as<std::string>()));
                }
                else if(className)
                {
                    list.push_back(moduleManager->getModule(className.as<std::string>()));
                }
                else //this is a class set, so look up every module in the set (by className)
                {
                    YAML::Node classSet = submodules[i]["classSet"];

                    for(size_t j=0; j<classSet.size(); j++)
                    {
                        YAML::Node theClassName = classSet[j];
                        list.push_back(moduleManager->getModule(theClassName.as<std::string>()));
                    }

                }

            }
        }
    }
    
    if(!found)
    {
        LOG_ERROR << "NO SUBMODULES FOUND FOR MODULE:" << parentModuleName;
        throw RuntimeException("Unable to find submodules", RuntimeException::CONFIGURATION_ERROR);
    }

    return list;
}

//see ConfigInterface::isParam
bool ConfigManager::isParam(std::string moduleName, std::string paramName)
{
    YAML::Node value = findConfigParam(moduleName, paramName);
    return static_cast<bool>(value);
}

//see ConfigInterface::getAllParams
std::string ConfigManager::getAllParams(std::string moduleName)
{
    const YAML::Node& module_root = theConfig[moduleName];
    std::string str = "Module name " + moduleName + "was not found";

    if (module_root)
    {
        str = getNodeAsString(module_root);
    }

    return str;
}

//see ConfigInterface::getAllParamsYAML
std::string ConfigManager::getAllParamsYAML(std::string moduleName)
{
    const YAML::Node& module_root = theConfig[moduleName];
    std::string str = "Module name " + moduleName + "was not found";

    if (module_root)
    {
        str = getNodeAsYAML(module_root);
    }

    return str;
}

//see ConfigInterface::getStringParam
std::string ConfigManager::getStringParam(std::string moduleName, std::string paramName)
{
    return getParam<std::string>(moduleName, paramName);
}

//see ConfigInterface::getStringParam
std::string ConfigManager::getStringParam(std::string moduleName, std::string paramName, std::string defaultValue)
{
    return getParam<std::string>(moduleName, paramName, defaultValue);
}

//see ConfigInterface::getStringVectorParam
std::vector<std::string> ConfigManager::getStringVectorParam(std::string moduleName, std::string paramName)
{
    return getParam<std::vector<std::string>>(moduleName, paramName);
}

//see ConfigInterface::getStringVectorParam
std::vector<std::string> ConfigManager::getStringVectorParam(std::string moduleName, std::string paramName, std::vector<std::string> defaultValue)
{
    return getParam<std::vector<std::string>>(moduleName, paramName, defaultValue);
}

//see ConfigInterface::getIntParam
int ConfigManager::getIntParam(std::string moduleName, std::string paramName)
{
    return getParam<int>(moduleName, paramName);
}

//see ConfigInterface::getIntParam
int ConfigManager::getIntParam(std::string moduleName, std::string paramName, int defaultValue)
{
    return getParam<int>(moduleName, paramName, defaultValue);
}

//see ConfigInterface::getIntVectorParam
std::vector<int> ConfigManager::getIntVectorParam(std::string moduleName, std::string paramName)
{
    return getParam<std::vector<int>>(moduleName, paramName);
}

//see ConfigInterface::getIntVectorParam
std::vector<int> ConfigManager::getIntVectorParam(std::string moduleName, std::string paramName, std::vector<int> defaultValue)
{
    return getParam<std::vector<int>>(moduleName, paramName, defaultValue);
}

//see ConfigInterface::getFloatParam
float ConfigManager::getFloatParam(std::string moduleName, std::string paramName)
{
    return getParam<float>(moduleName, paramName);
}

//see ConfigInterface::getFloatParam
float ConfigManager::getFloatParam(std::string moduleName, std::string paramName, float defaultValue)
{
    return getParam<float>(moduleName, paramName, defaultValue);
}

//see ConfigInterface::getFloatVectorParam
std::vector<float> ConfigManager::getFloatVectorParam(std::string moduleName, std::string paramName)
{
    return getParam<std::vector<float>>(moduleName, paramName);
}

//see ConfigInterface::getFloatVectorParam
std::vector<float> ConfigManager::getFloatVectorParam(std::string moduleName, std::string paramName, std::vector<float> defaultValue)
{
    return getParam<std::vector<float>>(moduleName, paramName, defaultValue);
}

//see ConfigInterface::getBoolParam
bool ConfigManager::getBoolParam(std::string moduleName, std::string paramName)
{
    bool option = getParam<bool>(moduleName, paramName);
    return option;
}

//see ConfigInterface::getBoolParam
bool ConfigManager::getBoolParam(std::string moduleName, std::string paramName, bool defaultValue)
{
    bool option = getParam<bool>(moduleName, paramName, defaultValue);
    return option;
}


//--------------------Private Helper Methods------------------------//

/**
 * @brief Helper method to find a configuration section in the yaml config file
 * 
 * @param name the section name
 * @return YAML::Node the configuration section
 */
YAML::Node ConfigManager::findConfig(std::string name)
{
    YAML::Node theNode = theConfig[name];
    return theNode;
}

/**
 * @brief Helper method to find a configuration section in the yaml config file
 * This differs from findConfig in that an exception will be thrown if the section isn't present
 * 
 * @param name the section name
 * @return YAML::Node the configuration section
 * @throws RuntimeException if the config section is not found
 */
YAML::Node ConfigManager::findRequiredConfig(std::string name)
{
    YAML::Node theNode = findConfig(name);
    if(!theNode)
    {
        LOG_ERROR << name << " not found in config";
        throw RuntimeException("Missing required configuration section", RuntimeException::CONFIGURATION_ERROR);
    }
    return theNode;
}


/**
 * @brief Helper method to retrieve the YAML node associated with a particular config parameter
 * 
 * This will search the module specific config.
 * 
 * @param moduleName the module name for the moduled requesting the config param
 * @param paramName the name of the parameter
 * @return YAML::Node 
 */
YAML::Node ConfigManager::findConfigParam(std::string moduleName, std::string paramName)
{
    YAML::Node value(YAML::NodeType::Undefined);

    //First check local param list
    YAML::Node paramList = findConfig(moduleName);
    if(paramList)
    {
        value = paramList[paramName];
    }
    
    return value;
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
template<typename T> T  ConfigManager::getParam(std::string moduleName, std::string paramName)
{
    YAML::Node value = findConfigParam(moduleName, paramName);
    if(value)
    {
        return value.as<T>();
    }
    else
    {
        LOG_ERROR << moduleName << " requires parameter " << paramName << " which was not found.";
        LOG_ERROR << "List of module parameters found: " << getAllParams(moduleName);
        throw RuntimeException("Missing required parameter", RuntimeException::CONFIGURATION_ERROR);
    }
}

/**
 * @brief Helper method to find an optional cofiguration parameter
 * This templated method is used as the implemenation for all of the getXXXConfig
 * methods required by ConfigInterface.
 * 
 * @tparam T the type to retrieve
 * @param moduleName the name of the module requesting the configuration parameter
 * @param paramName the name of the parameter (must match the config file)
 * @param defaultValue the default value to use if the config option is not found in the config files
 * @return T the configuration value
 * @throws RuntimeExcepttion if the parameter is not found
 */
template<typename T> T ConfigManager::getParam(std::string moduleName, std::string paramName, T defaultValue)
{
    T result = defaultValue;

    YAML::Node value = findConfigParam(moduleName, paramName);
    if(value)
    {
        result = value.as<T>();
    }

    return result;
}

std::string ConfigManager::getModuleName(int id)
{
    return moduleManager->getModuleName(id);
}
