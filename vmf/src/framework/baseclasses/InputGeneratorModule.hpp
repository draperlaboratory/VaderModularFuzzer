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

#include "StorageUserModule.hpp"
#include "StorageEntry.hpp"
#include "Logging.hpp"

namespace vmf
{
/**
 * @brief Base class for VMF Input Generators
 *
 * InputGenerator modules create new inputs that will be run by the Executor Module(s).  
 * InputGenerator modules that use mutation based strategies typically have configurable 
 * submodules of type MutatorModule.
 *
 */
class InputGeneratorModule: public StorageUserModule {
public:
    virtual void registerStorageNeeds(StorageRegistry& registry) = 0;
    virtual void registerMetadataNeeds(StorageRegistry& registry) {};

    /**
     * @brief Examine test case results (called prior to addNewTestCases)
     *
     * This is an optional method of InputGeneration.  InputGenerators that need
     * to look at the results of their test case runs prior to generating new test
     * cases should implement this method.  It is distinct from addNewTestCases
     * in that the storage new list has not yet been cleared when this method is called.
     *
     * Implementors of this method should be aware that configurations with more than one
     * input generator will result in StorageEntries in the fuzzing loop that were not created
     * by this input generator.  Implementors of this method that only care about their own StorageEntries
     * will need to tag or otherwise write identifying information to those StorageEntries
     * such that they can be easily identified when this method is called.
     * 
     * The default implementation of this method always returns false, indicating that the
     * input generator is not complete.  Only some input generators will have a concept of completeness,
     * those that do not should just always return false.
     * 
     * @param storage the storage module
     * @return true if the input generator is "complete", and false otherwise.
     */
    virtual bool examineTestCaseResults(StorageModule& storage) {return false;};

    /**
     * @brief Create one or more new test cases
     *
     * One or more new test cases should be created
     *
     * @param storage the storage module
     */
    virtual void addNewTestCases(StorageModule& storage) = 0;

    virtual ~InputGeneratorModule() {};

  /**
     * @brief Helper method to return a single InputGenerator submodule from config
     * This method will retrieve a single InputGenerator submodules for the specified parent modules.
     * If there are no InputGenerator submodules, then an nullptr will be returned.  If there are more
     * than one InputGenerator submodules specified, than an exception will be thrown.  Use the list form
     * of this method getInputGeneratorSubmodules(), if more than one InputGenerator module can be specified.
     * 
     * @param config the ConfigInterface object
     * @param parentName the name of the parent module
     * @return InputGeneratorModule* the submodule, or nullptr if none is specified
     */
    static InputGeneratorModule* getInputGeneratorSubmodule(ConfigInterface& config, std::string parentName)
    {
        InputGeneratorModule* theModule = nullptr;
        std::vector<Module*> modules = config.getSubModules(parentName);
        for(Module* m: modules)
        {
            if(isAnInstance(m))
            {
                if(nullptr == theModule)
                {
                    theModule = castTo(m);
                }
                else
                {
                    throw RuntimeException(
                        "Configuration file contained more than one InputGenerator module, but only one is supported",
                        RuntimeException::CONFIGURATION_ERROR);
                }
                
            }
        }
        return theModule;
    }

    /**
     * @brief Helper method to return a single InputGenerator submodule from config by name
     * This method will retrieve a single InputGenerator submodule by name for the specified parent modules.
     * If there are no InputGenerator submodules with the specified name, then an nullptr will be returned.  
     * 
     * @param config the ConfigInterface object
     * @param parentName the name of the parent module
     * @param childName the name of the child module to finde
     * @return InputGeneratorModule* the submodule, or nullptr if none is found
     */
    static InputGeneratorModule* getInputGeneratorSubmoduleByName(ConfigInterface& config, std::string parentName, std::string childName)
    {
        InputGeneratorModule* theModule = nullptr;
        std::vector<Module*> modules = config.getSubModules(parentName);
        for(Module* m: modules)
        {
            if(childName == m->getModuleName())
            {
                if(isAnInstance(m))
                {
                    theModule = castTo(m);
                    break;
                }
                else
                {
                    LOG_ERROR << parentName << " requested an InputGenerator submodule named " << childName 
                               << ", but that submodules is not of type InputGenerator.";
                    throw RuntimeException(
                        "Configuration file contained a module with this name, but it was not an executor module",
                        RuntimeException::CONFIGURATION_ERROR);
                }
            }
        }
        return theModule;
    }

    /**
     * @brief Helper method to get the InputGenerator Submodules from config
     * This method will retrieve all of the InputGenerator submodules for the specified parent modules.
     * If there are no InputGenerator submodules, then an empty list will be returned.
     * 
     * @param config the ConfigInterface object
     * @param parentName the name of the parent module
     * @return std::vector<InputGeneratorModule*> the list of submodules
     */
    static std::vector<InputGeneratorModule*> getInputGeneratorSubmodules(ConfigInterface& config, std::string parentName)
    {
        std::vector<InputGeneratorModule*> list;
        std::vector<Module*> modules = config.getSubModules(parentName);
        for(Module* m: modules)
        {
            if(isAnInstance(m))
            {
                list.push_back(castTo(m));
            }
        }
        return list;
    }

    /**
     * @brief Convenience method to determine if a module is actually an input generator
     * 
     * @param module 
     * @return true if this module has a module type=INPUT_GENERATOR
     * @return false 
     */
    static bool isAnInstance(Module* module)
    {
        ModuleTypeEnum type = module->getModuleType();
        return (ModuleTypeEnum::INPUT_GENERATOR == type);
    }

    /**
     * @brief Convenience method to cast Module* to InputGeneratorModule*
     * 
     * Call isAnInstance first to check the type in order to avoid an exception.
     * 
     * @param module 
     * @return InputGeneratorModule* 
     * @throws RuntimeException if the underlying Module* is not a decendant of InputGeneratorModule
     */
    static InputGeneratorModule* castTo(Module* module)
    {
        InputGeneratorModule* inpGen;
        if(nullptr != module)
        {
            inpGen = dynamic_cast<InputGeneratorModule*>(module);
        
            if(nullptr == inpGen)
            {
                throw RuntimeException("Failed attempt to cast module to InputGenerator",
                                    RuntimeException::USAGE_ERROR);
            }
        }
        else
        {
            throw RuntimeException("Attempt to cast nullptr to InputGenerator",
                                   RuntimeException::UNEXPECTED_ERROR);
        }
        return inpGen;
    }

protected:
    /**
     * @brief Construct a new Input Generator Module 
     * 
     * @param name the name of the module
     */
    InputGeneratorModule(std::string name) : StorageUserModule(name, ModuleTypeEnum::INPUT_GENERATOR) {};
};
}
