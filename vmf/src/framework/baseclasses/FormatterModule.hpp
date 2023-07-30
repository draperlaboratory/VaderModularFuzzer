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
#include "RuntimeException.hpp"

namespace vader
{
/**
 * @brief The base class for all Vader formatted modules.
 *
 * Formatter modules modify new test cases to provide any custom formatting needed for the SUT.
 *
 */
class FormatterModule: public Module
{
public:
    /**
     * @brief Modify the provided input buffer to perform any SUT specific formatting
     * 
     * The test case must be copied to the output buffer, with any formatting modifications made.
     * The size of the resulting formatted test case is returned.
     * 
     * NOTE: THE INPUT BUFFER MAY NOT BE MODIFIED IN PLACE
     * 
     * @param inputBuff the input buffer
     * @param inputBuffSize the size of the input buffer
     * @param outputBuff the output buffer
     * @param outputBuffSize the maximum size of the output buffer
     * @return int the actual size of the modified test case in outputBuff
     */
    virtual int modifyTestCase(char* inputBuff, int inputBuffSize, char* outputBuff, int outputBuffSize) = 0;
    virtual ~FormatterModule() {};
    
    /**
     * @brief Helper method to return a single Formatter submodule from config
     * This method will retrieve a single Formatter submodules for the specified parent modules.
     * If there are no Formatter submodules, then an nullptr will be returned.  If there are more
     * than one Formatter submodules specified, than an exception will be thrown.  Use the list form
     * of this method getFormatterSubmodules(), if more than one Formatter module can be specified.
     * 
     * @param config the ConfigInterface object
     * @param parentName the name of the parent module
     * @return FormatterModule* the submodule, or nullptr if none is specified
     */
    static FormatterModule* getFormatterSubmodule(ConfigInterface& config, std::string parentName)
    {
        FormatterModule* theModule = nullptr;
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
                        "Configuration file contained more than one Formatter module, but only one is supported",
                        RuntimeException::CONFIGURATION_ERROR);
                }
                
            }
        }
        return theModule;
    }

    /**
     * @brief Helper method to get the Formatter Submodules from config
     * This method will retrieve all of the Formatter submodules for the specified parent modules.
     * If there are no Formatter submodules, then an empty list will be returned.
     * 
     * @param config the ConfigInterface object
     * @param parentName the name of the parent module
     * @return std::vector<FormatterModule*> the list of submodules
     */
    static std::vector<FormatterModule*> getFormatterSubmodules(ConfigInterface& config, std::string parentName)
    {
        std::vector<FormatterModule*> list;
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
     * @brief Convenience method to determine if a module is actually a formatter
     * 
     * @param module 
     * @return true if this module has a module type=FORMATTER
     * @return false 
     */
    static bool isAnInstance(Module* module)
    {
        ModuleTypeEnum type = module->getModuleType();
        return (ModuleTypeEnum::FORMATTER == type);
    }

    /**
     * @brief Convenience method to cast Module* to FormatterModule*
     * 
     * Call isAnInstance first to check the type in order to avoid an exception.
     * 
     * @param module 
     * @return FormatterModule* 
     * @throws RuntimeException if the underlying Module* is not a decendant of FormatterModule
     */
    static FormatterModule* castTo(Module* module)
    {
        FormatterModule* f;
        if(nullptr != module)
        {
            f = dynamic_cast<FormatterModule*>(module);
        
            if(nullptr == f)
            {
                throw RuntimeException("Failed attempt to cast module to Formatter",
                                    RuntimeException::USAGE_ERROR);
            }
        }
        else
        {
            throw RuntimeException("Attempt to cast nullptr to Formatter",
                                   RuntimeException::UNEXPECTED_ERROR);
        }
        return f;
    }

protected:
    /**
     * @brief Construct a new Formatter Module object
     * 
     * @param name the name of the module
     */
    FormatterModule(std::string name) : Module(name, ModuleTypeEnum::FORMATTER) {};
};
}