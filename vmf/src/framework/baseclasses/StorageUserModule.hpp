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
#include "StorageModule.hpp"
#include "StorageRegistry.hpp"

namespace vader
{

/**
 * @brief Base class for all modules that read or write to storage
 * 
 * This is the base class for any module types that are users of storage.
 * Users of storage must register their storage needs up front, in
 * order to validate the configuration of Vader.  This is a pure virtual
 * class that cannot be instantiated directly.
 * 
 */
class StorageUserModule: public Module
{
public:
     /**
     * @brief All modules must notify the registry regarding the fields that they intend to read or write
     *
     * To notify the registry of the use of a data field call
     * registry.registerKey("KEY_NAME", data_type, access_type).  To notify the registry of the use of a tag,
     * call registry.registerTag("TAG_NAME").  Both registration calls will return an integer handle that should
     * be used for subsequent acesss to the variable or tag.
     *
     * @param registry the registry object to register with
     */
    virtual void registerStorageNeeds(StorageRegistry& registry) = 0;


    /**
     * @brief Modules using global metadata must also register fields that they intend to read or write
     *
     * Not all modules use metadata (which is summary data collected across the entries stored in storage),
     * hence this is an optional method.
     *
     * @param registry
     */
    virtual void registerMetadataNeeds(StorageRegistry& registry) {};

    using Module::shutdown; //Inform compiler that we want both versions of shutdown
    /** @brief Perform any shutdown processing that relies on storage
     * 
     * Similar to the shutdown() method, only this version of the method is provided
     * with a reference to storage.  StorageUserModules may implement this version of the
     * method, the version without a storage parameter (defined in the base Module class),
     * or both.
     * 
     * @param storage 
     */
    virtual void shutdown(StorageModule& storage) {};
protected:
    /**
     * @brief Construct a new Storage User Module object
     * 
     * @param name the name of the module
     * @param myType the type of the module
     */
    StorageUserModule(std::string name, ModuleTypeEnum myType) : Module(name, myType) {};

};
}
