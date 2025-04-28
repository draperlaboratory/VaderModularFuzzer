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
#include "RuntimeException.hpp"
#include <iostream>
#include <string>

namespace vmf
{
class ConfigInterface; //Forward-declaration

/**
 * @brief Module is a base class for all configurable elements within VMF
 *
 * Module is pure virtual class that cannot be instantiated.  It is the base class for all other
 * VMF module base classes.
 *
 */
class Module {
public:

    ///The list of valid module types
    enum ModuleTypeEnum
    {
        CONTROLLER,
        EXECUTOR,
        FEEDBACK,
        INITIALIZATION,
        INPUT_GENERATOR,
        MUTATOR,
        OUTPUT,
        STORAGE
    };

    /**
     * @brief All modules must read any configuration settings from the config method
     * 
     * This must include requesting any dependent modules from config.
     * 
     * @param config 
     */
    virtual void init(ConfigInterface& config) = 0;

    /** @brief Perform any shutdown  processing
     * 
     * Many modules may wish to peform special processing when the application is
     * shutdown (such as writing any final data to disk, or running one more time on
     * any outputs that haven't been processed yet).  This method is optional.
     */
    virtual void shutdown() {};

    virtual ~Module() {};

    /**
     * @brief Get the name of the module
     * This is a unique brief descriptive name of the module that is used to map configuration
     * information to module instances.
     * 
     * @return std::string 
     */
    std::string getModuleName()
    {
        return myName;
    }

    /**
     * @brief Get the module type
     * This will identify the underlying type of the module
     * 
     * @return ModuleTypeEnum the module type
     */
    ModuleTypeEnum getModuleType()
    {
        return myType;
    }

    /**
     * @brief Sets a unique identifier each module instance
     *
     * @param id unique ID to identify module instance
     * @throws RuntimeException if this method is called more than once per module instance
     */
    void setID(int id)
    {
        if (hasId)
            throw RuntimeException("This module already has an ID", RuntimeException::UNEXPECTED_ERROR);

        myId = id;
        hasId = true;
    }

    /**
     * @brief Creates and returns a new unique identifier
     *
     * @return int the module's unique ID
     */
    int getID()
    {
        return myId;
    }

protected:

    /**
     * @brief Construct a new Module object
     * 
     * @param name the name of the module
     * @param type the type of the module
     */
    Module(std::string name, ModuleTypeEnum type){
         myName = name;
         myType = type;
         hasId = false;
    };

private:
    std::string myName;
    ModuleTypeEnum myType;
    int myId;
    bool hasId;
};
}
