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
#include "ConfigManager.hpp"
#include "RuntimeException.hpp"
#include "Logging.hpp"
#include "StorageUserModule.hpp"
#include <map>
#include <vector>
#include <iostream>
#include <fstream>
#include <filesystem>

using namespace vader;


/**
 * @brief Construct a new Config Manager object
 * Note that the configuration files are not read until loadModules() is called.
 * 
 * @param filenames the list of configuration filenames to read
 */
ConfigManager::ConfigManager(std::vector<std::string> filenames) 
{
    this->filenames = filenames;
    this->configCount = 0;
}

/**
 * @brief Destroy the Config Manager object
 * This deletes all of the modules that were build by this object based
 * on the provided configuration information
 * 
 */
ConfigManager::~ConfigManager()
{
    resetModuleRegistry();
}

/**
 * @brief Helper method to delete all of the built modules and clear the module registry
 * This is called automatically in the destructor, but may also be called at other
 * times to fully clear the currently loaded modules.
 */
void ConfigManager::resetModuleRegistry()
{
    //Delete all of the built modules
    for (const auto &module : moduleRegistry) 
    {
        Module* mPtr = module.second;
        delete mPtr;
    }

    moduleRegistry.clear();
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
            int size = inFile.tellg();
            std::string thisInput(size,' ');

            // read file contents into string
            inFile.seekg(0, inFile.beg);
            inFile.read(&thisInput[0], size);
 
            // if the input file's contents contains the string 'vmfVariables' 
            // then pre-pend vs append its contents to the string containing all input file's contents

            const auto pos = thisInput.find(VMF_VARIABLES_KEY);

            if (std::string::npos != pos)
            {
                // pre-pend this file's contents
                theConfigAsString.insert(0, thisInput);
            }
            else
            {
                // append this file's contents
                theConfigAsString.append(thisInput);
            }

            // append newline character
            theConfigAsString += "\n";
        } 
        else 
        {
            // logger not initialized yet at this point
            std::cout << "ERROR: Unable to open input file: " << file << "\n" << std::flush;
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
        std::cerr << e.what() << '\n';
        throw RuntimeException("Error parsing YAML config file", RuntimeException::CONFIGURATION_ERROR);
    }

}

/**
 * @brief Adds additional yaml configuration information to the config manager
 * 
 * @param cfg the yaml to add
 */
void ConfigManager::addConfig(std::string cfg)
{
    // if the input yaml's contents contains the string 'vmfVariables' 
    // then pre-pend vs append its contents to the string containing all input file's contents

    const auto pos = cfg.find(VMF_VARIABLES_KEY);

    if (std::string::npos != pos)
    {
        // pre-pend this yaml's contents
        theConfigAsString.insert(0, cfg);
        theConfigAsString += "\n";
    }
    else
    {
        // append this yaml's contents
        theConfigAsString += "\n";
        theConfigAsString.append(cfg);
    }

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
    YAML::Node modules = findRequiredConfig(ConfigInterface::VMF_MODULES_KEY);

    if(modules.Type() == YAML::NodeType::Map)
    {
        //Build storage module
        YAML::Node storage = modules[ConfigInterface::STORAGE_MODULE_KEY];
        if(storage)
        {
            YAML::Node className = storage["className"];
            if(className)
            {
                buildModule(className.as<std::string>(), ConfigInterface::STORAGE_MODULE_KEY);
            }
        }

        //Build controller module
        YAML::Node root = modules[ConfigInterface::ROOT_MODULE_KEY];
        if(root)
        {
            YAML::Node className = root["className"];
            if(className)
            {
                buildModule(className.as<std::string>(), ConfigInterface::ROOT_MODULE_KEY);
            }

            std::vector<std::string> childNodes = buildChildren(root);
            //Now build any additional child modules (that are not direct children of root)
            for(std::string childName: childNodes)
            {
                YAML::Node child = modules[childName];
                if(child)
                {
                    buildChildren(child);
                    //No further recursion is needed, given the config file structure
                }
            }
        }
    }
    else
    {
        throw RuntimeException("Unable to parse list of modules from config file",
                  RuntimeException::CONFIGURATION_ERROR);
    }

   //Now initialize all of the modules that were just build
   for (const auto &module : moduleRegistry) {

        Module* m = module.second;
        LOG_DEBUG << "   INITIALIZING: " << module.first;
        m->init(*this);
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
    if(children)
    {
        if(children.Type() == YAML::NodeType::Sequence)
        {
            for(size_t i=0; i<children.size(); i++)
            {
                //Load the className and optional id for each module
                YAML::Node id = children[i]["id"];
                YAML::Node className = children[i]["className"];
                std::string classNameString = className.as<std::string>();
                if(id)
                {
                    //Build the module if it doesn't already exist
                    std::string idString = id.as<std::string>();
                    if(moduleRegistry.count(idString)==0)
                    {
                        buildModule(classNameString, idString);
                        childList.push_back(idString);
                    }
                }
                else
                {
                    //Build the module if it doesn't already exist
                    if(moduleRegistry.count(classNameString)==0)
                    {
                        buildModule(classNameString);
                        childList.push_back(classNameString);
                    }
                }
            }
        }
    }

    return childList;
}

/**
 * @brief Call upon all of the modules to shutdown
 * 
 * This method calls shutdown on all module types, and shutdown(storage)
 * on all StorageUserModules.  No order is specified for these calls *except* that
 * the root module will be shutdown second to last, and the storage module will
 * be shutdown last.
 * 
 * @param storage storage module to provide at shutdown (this could technically
 * be retrieved by this module, but the caller will have this information more
 * readily accessible)
 */
void ConfigManager::shutdownModules(StorageModule& storage)
{
    Module* storageModule = nullptr;
    Module* rootModule = nullptr;
    for (const auto &module : moduleRegistry) 
    {
        std::string key = module.first;
        //If this is the storage or root module, save it for the end
        if(STORAGE_MODULE_KEY == key)
        {
            storageModule = module.second;
        }
        else if(ROOT_MODULE_KEY == key)
        {
            rootModule = module.second;
        }
        else //go ahead and shutdown the module
        {
            callShutdown(module.second, storage);
        }
            
    }

    //Now shutdown the root module and storage module (assuming they were found)
    if(nullptr != rootModule)
    {
        callShutdown(rootModule,storage);
    }
    if(nullptr != storageModule)
    {
        storageModule->shutdown(); //the storage module cannot be a storage user, by definition
    }
}

/**
 * @brief Helper method to call the shutdown methods on the specified module
 * 
 * @param module the module to shutdown
 * @param storage the storage module to pass to shutdown(storage) for StorageUserModules
 */
void ConfigManager::callShutdown(Module* module, StorageModule& storage)
{
    //Call shutdown
    module->shutdown();

    //If this is a StorageUserModule, call storage(shutdown) as well
    StorageUserModule* sum = dynamic_cast<StorageUserModule*>(module);
    if(nullptr != sum)
    {
        sum->shutdown(storage);
    }
}

/**
 * @brief Call upon all of the StorageUserModules to register their storage needs
 * Note: loadModules() must be called first, otherwise there are no instantiated
 * modules yet to register with storage.
 * This method calls registerStorageNeeds() and registerMetadataNeeds() on each
 * StorageUserModule that has been loaded.
 * 
 * @param registry the main storage registry
 * @param metadata the metadata storage registry
 */
void ConfigManager::registerModuleStorageNeeds(StorageRegistry* registry, StorageRegistry* metadata)
{
    for (const auto &module : moduleRegistry) 
    {
        Module* m = module.second;
        StorageUserModule* sum = dynamic_cast<StorageUserModule*>(m);
        if(nullptr != sum)
        {
            sum->registerStorageNeeds(*registry);
            sum->registerMetadataNeeds(*metadata);
        }
        //otherwise this is a Module that is not a subclass of StorageUserModule
        //and hence it has no storage needs to be registered
            
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
 * @brief Returns the root module
 * This is the module that is configured with name "controller" in the config files(s).
 * 
 * @return Module* the root module
 * @throws RuntimException if there is no root module
 */
Module* ConfigManager::getRootModule()
{
    std::map<std::string, Module*>::iterator it = moduleRegistry.find(ROOT_MODULE_KEY);
      
    if(it == moduleRegistry.end())
    {
        throw RuntimeException("No root module defined in the config file.", RuntimeException::CONFIGURATION_ERROR);
    }
    else
    {
        return it->second;
    }
}

/**
 * @brief Returns the storage module
 * This is the module that is configured with name "storage" in the config files(s).
 * 
 * @return Module* the storage module
 * @throws RuntimException if there is no storage module
 */
Module* ConfigManager::getStorageModule()
{
    std::map<std::string, Module*>::iterator it = moduleRegistry.find(STORAGE_MODULE_KEY);
      
    if(it == moduleRegistry.end())
    {
        throw RuntimeException("No storage module defined in the config file.", RuntimeException::CONFIGURATION_ERROR);
    }
    else
    {
        return it->second;
    }
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
    YAML::Node modulesSection = findRequiredConfig(ConfigInterface::VMF_MODULES_KEY);
    YAML::Node submodulesSection = modulesSection[parentModuleName];
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
                    list.push_back(lookupModule(id.as<std::string>()));
                }
                else
                {
                    list.push_back(lookupModule(className.as<std::string>()));
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
 * @brief Helper method to build a module
 * This version uses the className as the default module name.
 * 
 * @param className the name of the class
 */
void ConfigManager::buildModule(std::string className)
{
    buildModule(className, className);
}

/**
 * @brief Helper method to build a module
 * The name parameter is the name that the module will be referred to by.
 * This must be a unique name in each configuration.
 * 
 * @param className the name of the class
 * @param name the name of the module
 * @throws RuntimeException if the module name is not unique
 */
void ConfigManager::buildModule(std::string className, std::string name)
{
    //Check that the name is not already defined in the registry
    if(moduleRegistry.count(name)>0)
    {
        LOG_ERROR << "Vader configuration contains more than one module named " << name;
        throw RuntimeException("Duplicate module name in the configuration.", RuntimeException::CONFIGURATION_ERROR);
    }

    //Build module and add to registry
    moduleRegistry[name] = ModuleFactory::getInstance().buildModule(className, name);
    LOG_INFO << "LOADING: " << name << " module (instance of " << className << ")"; 
}

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
 * @brief Helper method to lookup module by name
 * 
 * @param name the name to lookup
 * @return Module* the pointer to the module
 * @throws RuntimeException if the module cannot be found
 */
Module* ConfigManager::lookupModule(std::string name)
{
    Module* m = moduleRegistry[name];
    if(nullptr == m)
    {
        LOG_ERROR << "UNKNOWN MODULE:" << name;
        throw RuntimeException("Unknown module name included in config",
                               RuntimeException::CONFIGURATION_ERROR);
    }
    return m;
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
