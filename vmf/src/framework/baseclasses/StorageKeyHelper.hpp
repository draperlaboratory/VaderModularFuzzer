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
#include "StorageRegistry.hpp"
#include "RuntimeException.hpp"

namespace vmf
{
/**
 * @brief This is a helper class for handling keys in storage
 *
 */
class StorageKeyHelper
{
public:
    //Type masks are in the top nibble of the handle returned during registration.
    //As such, they may only use the values 0-15.
    //Note: If adding a new type, add to the typeToString method below as well
    ///Bit mask for values of type tag
    static const int TAG_TYPE_MASK = 0; 
    ///Bit mask for values of type int
    static const int INT_TYPE_MASK = 1; 
    ///Bit mask for values of type unsigned int
    static const int UINT_TYPE_MASK = 2; 
    ///Bit mask for values of type unsigned long long (64 bit)
    static const int U64_TYPE_MASK = 3; 
    ///Bit mask for values of type float
    static const int FLOAT_TYPE_MASK = 4; 
    ///Bit mask for values of type buffer
    static const int BUFFER_TYPE_MASK = 5; 
    ///Bit mask for values of type temp buffer
    static const int BUFFER_TEMP_TYPE_MASK = 6; 
    //const int MAX_TYPE_MASK = 15;

    /**
     * @brief Helper function to retrieve the type of a key
     * The return value should be one of the _TYPE_MASK constants, as long
     * as the provided value is a valid key.
     * 
     * @param handle the handle to parse
     * @return int the type mask
     */
    static inline int getType(int handle)
    {
        //& operator is needed in case the top bit is set so that the value doesn't remain negative
        return ((handle >> 28) & (0x000000F)); 
    }  

    /**
     * @brief Helper function to retrieve the actual index into the underlying data storage
     * The return value should be the index with the bit mask removed.
     * 
     * @param handle the handle to parse
     * @return int the index
     */
    static inline int getIndex(int handle)
    {
        return (handle & 0x0FFFFFFF); //Removing the top 4 bits, which is the mask
    }  

    /**
     * @brief Helper method to add the type information to an index
     * This produces the handle that should be returned to users of storage
     * 
     * @param index the index into the underlying data storage 
     * @param mask the type mask to add to the value
     * @return int the handle
     */
    static inline int addTypeToIndex(int index, int mask)
    {
        int shiftedMask = mask << 28;
        return (index | shiftedMask);
    }

    /**
     * @brief Helper method to return a string representation of the data type
     * This is primarily useful in printing error messages.
     * 
     * @param typeMask the type mask value
     * @return std::string a string description of the provided type
     */
    static std::string typeToString(int typeMask)
    {
        if(TAG_TYPE_MASK==typeMask)
        {
            return "TAG";
        }
        if(INT_TYPE_MASK==typeMask)
        {
            return "INT";
        }
        if(UINT_TYPE_MASK==typeMask)
        {
            return "UINT";
        }
        if(U64_TYPE_MASK==typeMask)
        {
            return "U64";
        }
        if(FLOAT_TYPE_MASK==typeMask)
        {
            return "FLOAT";
        }
        if(BUFFER_TYPE_MASK==typeMask)
        {
            return "BUFFER";
        }
        if(BUFFER_TEMP_TYPE_MASK==typeMask)
        {
            return "BUFFER_TEMP";
        }
        return "UNKNOWN TYPE";
    }

    /**
     * @brief Helper method to convert the type mask to an enum
     * Note that this cannot be called with the TAG_TYPE_MASK, as tags do not
     * have a corresponding storageTypes enum value.
     * 
     * @param typeMask the type mask value
     * @return StorageRegistry::storageTypes the enum corresponding with the type mask
     * @throws RuntimeException if the provided parameter is not a valid type mask
     */
    static StorageRegistry::storageTypes typeToEnum(int typeMask)
    {
        if(INT_TYPE_MASK==typeMask)
        {
            return StorageRegistry::INT;
        }
        if(UINT_TYPE_MASK==typeMask)
        {
            return StorageRegistry::UINT;
        }
        if(U64_TYPE_MASK==typeMask)
        {
            return StorageRegistry::U64;
        }
        if(FLOAT_TYPE_MASK==typeMask)
        {
            return StorageRegistry::FLOAT;
        }
        if(BUFFER_TYPE_MASK==typeMask)
        {
            return StorageRegistry::BUFFER;
        }
        if(BUFFER_TEMP_TYPE_MASK==typeMask)
        {
            return StorageRegistry::BUFFER_TEMP;
        }
        throw RuntimeException("Unknown type provided to this function", RuntimeException::USAGE_ERROR);
    }

        /**
     * @brief Helper method to convert an enum to a type mask
     * Note that this cannot be called with the TAG_TYPE_MASK, as tags do not
     * have a corresponding storageTypes enum value.
     *
     * @param enumVal the enum corresponding with the type mask
     * @return int the type mask value
     */
    static int enumToType(StorageRegistry::storageTypes enumVal)
    {
        if(StorageRegistry::INT == enumVal)
        {
            return INT_TYPE_MASK;
        }
        if(StorageRegistry::UINT == enumVal)
        {
            return UINT_TYPE_MASK;
        }
        if(StorageRegistry::U64 == enumVal)
        {
            return U64_TYPE_MASK;
        }
        if(StorageRegistry::FLOAT == enumVal)
        {
            return FLOAT_TYPE_MASK;
        }
        if(StorageRegistry::BUFFER == enumVal)
        {
            return BUFFER_TYPE_MASK;
        }
        if(StorageRegistry::BUFFER_TEMP == enumVal)
        {
            return BUFFER_TEMP_TYPE_MASK;
        }
        //This shouldn't be possible
        throw RuntimeException("Unknown type provided to this function", RuntimeException::USAGE_ERROR);
    }
};
}