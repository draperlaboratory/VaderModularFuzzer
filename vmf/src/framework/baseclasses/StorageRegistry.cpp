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
#include "StorageRegistry.hpp"
#include "RuntimeException.hpp"
#include "Logging.hpp"

using namespace vader;
using std::string;
using std::vector;

/**
 * @brief Construct a new Storage Registry object that is not sortable
 *
 * This registry will correspond with storage entries that do not have a sort by
 * key, and hence cannot be sorted (it is expected this will be used for metadata only)
 *
 */
StorageRegistry::StorageRegistry()
{
    sortByType          = BUFFER; //Buffer is an invalid sort by type for StorageEntries
    sortByKeyHandle     = -1;
    sortByOrder         =  sortOrder::ASCENDING;
    readAllTags         = false;
    writeAllTags        = false;
}

/**
 * @brief Construct a new sortable Storage Registry object
 *
 * This will automatically register the sort by key with storage.
 *
 * @param sortByKey the key to sort by
 * @param keyType the data type of the key
 * @param order the sorting order
 */
StorageRegistry::StorageRegistry(std::string sortByKey, storageTypes keyType, sortOrder order)
{
    sortByType = keyType;
    sortByKeyHandle = registerKey(sortByKey, sortByType, accessType::READ_ONLY);
    sortByOrder = order;
    readAllTags = false;
    writeAllTags = false;
}

/**
 * @brief Destroy the Storage Registry:: Storage Registry object
 *
 */
StorageRegistry::~StorageRegistry()
{

}

/**
 * @brief Helper method to convert string to storageTypes enum
 * 
 * @param type 
 * @return StorageRegistry::storageTypes 
 */
StorageRegistry::storageTypes StorageRegistry::stringToStorageType(std::string type)
{
    storageTypes enumVal = INT;
    if("FLOAT" == type)
    {
        enumVal = FLOAT;
    }
    else if("BUFFER" == type)
    {
        enumVal = BUFFER;
    }
    else if("INT" != type)
    {
        LOG_ERROR << "storageType specified is not a valid enum value: " << type;
        throw RuntimeException ("Invalid storageType specified", RuntimeException::USAGE_ERROR);
    }
    return enumVal;
}

/**
 * @brief Helper method to convert string to sortOrder enum
 * 
 * @param type 
 * @return StorageRegistry::sortOrder
 */
StorageRegistry::sortOrder StorageRegistry::stringToSortOrder(std::string type)
{
    sortOrder enumVal = DESCENDING;
    if("ASCENDING" == type)
    {
        enumVal = ASCENDING;
    }
    else if("DESCENDING" != type)
    {
        LOG_ERROR << "sortOrder specified is not a valid enum value: " << type;
        throw RuntimeException ("Invalid sortOrder specified", RuntimeException::USAGE_ERROR);
    }
    return enumVal;
}

/**
 * @brief Validates the registration
 *
 * This method ensures that all fields and tags have both readers and writers registered.
 * If there are readers but no writers, then the configuration is invalid.  Writers without readers are
 * treated as a warning (and the configuration is still considered valid).
 *
 * @return true if the configuration is valid
 * @return false otherwise
 */
bool StorageRegistry::validateRegistration()
{
    //Prior to validating tags, update the registration based on the readAllTags
    //and writeAllTags parameters
    if(readAllTags || writeAllTags)
    {
        int numTags = tagNames.size();
        for(int i=0; i<numTags; i++)
        {
            if(readAllTags)
            {
                tagNames[i].isRead = true;
            }
            if(writeAllTags)
            {
                tagNames[i].isWritten = true;
            }
        }
    }


    bool isValid = validateList(intKeys, "integer");
    isValid = isValid && validateList(floatKeys, "float");
    isValid = isValid && validateList(bufferKeys, "buffers");
    isValid = isValid && validateList(tagNames, "tags");

    return isValid;
}

/**
 * @brief Helper method to validate a list of keys
 *
 * @param keyList the registration metadata to validate
 * @param listName the name of the list (for logging purposes)
 * @return true if the registration if valid
 * @return false otherwise
 */
bool StorageRegistry::validateList(vector<registryInfo>& keyList, string listName)
{
    LOG_INFO << "StorageRegistry::Validating " << listName << " fields\n";

    bool isValid = true;
    for(registryInfo info: keyList)
    {
        if(info.isRead && !info.isWritten)
        {
            LOG_ERROR << info.name << " has no registered writer (though it is read)";
            isValid = false;
        }
        else if (!info.isRead && info.isWritten)
        {
            //Warning (registration is still valid, but inform user of unused data)
            LOG_WARNING << info.name << " has no registered reader (though it is written)";
        }
        else
        {
            LOG_INFO << info.name << " is valid";
        }
    }

    return isValid;
}

/**
 * @brief Register a key for a data field
 *
 * @param keyName the unique string name of the field
 * @param type the data type
 * @param access how the caller doing the registration will use the key
 * @return int the handle to use for subsequent access to the key (for getters and setters in the StorageEntry)
 */
int StorageRegistry::registerKey(string keyName, storageTypes type, accessType access)
{
    switch(type)
    {
    case INT:
        return addIfNotPresent(intKeys,keyName,access);
        break;
    case FLOAT:
        return addIfNotPresent(floatKeys,keyName,access);
        break;
    case BUFFER:
        return addIfNotPresent(bufferKeys,keyName,access);
        break;
    }

    //Shouldn't happen
    throw RuntimeException("Unknown key registration type", RuntimeException::UNEXPECTED_ERROR);
}

/**
 * @brief Register a tag
 *
 * @param tagName the unique string name for the tag
 * @param access how the caller doing the registration will use the tag
 * @return int the handle to use for subsequent access to the tag (for setting a tag via the Storage object)
 */
int StorageRegistry::registerTag(string tagName, accessType access)
{
    return addIfNotPresent(tagNames,tagName,access);
}

/**
 * @brief Register for all the tags in this storage registry
 * Note that because registration happens one module at a time, any module
 * that wants to use all of the tags must request the tag handles
 * after registration is complete.  The tag handles should be requested
 * directly from the StorageModule sometime after initialization is complete.
 * 
 * This capability is primarily useful for output modules.
 * 
 * @param access how the caller doing the registration will use the tag
 */
void StorageRegistry::registerForAllTags(accessType access)
{
    if((READ_ONLY == access)||(READ_WRITE == access))
    {
        readAllTags = true;
    }
    if((WRITE_ONLY == access)||(READ_WRITE == access))
    {
        writeAllTags = true;
    }

}

/**
 * @brief Returns the list of registered tag names
 * These are returned in a human readable form, in the order that the tags were registered in.
 * 
 * This method is used by the StorageModule to retrieve the tag names.  It should not be
 * called during registration, as it may return an incomplete list of tags.  Modules
 * that need the list of tags should retrieve them from storage after initialization is complete.
 * 
 * @return std::vector<std::string> 
 */
std::vector<std::string> StorageRegistry::getTagNames()
{
    std::vector<std::string> names;
    for(registryInfo info: tagNames)
    {
        names.push_back(info.name);
    }
    return names;
}

/**
 * @brief Returns the list of all tag handles
 * These are returned in the order that the tags were registered in (so they can be
 * mapped to the list returned by getTagNames).
 * 
 * This method is used by the StorageModule to retrieve the tag names.  It should not be
 * called during registration, as it may return an incomplete list of tags.  Modules
 * that need the list of tags should retrieve them from storage after initialization is complete.
 * 
 * @return std::vector<std::string> 
 */
std::vector<int> StorageRegistry::getTagHandles()
{
    std::vector<int> handles;

    //Here the tag handles are simple integer indices, so we can just count
    int i = 0;
    for(registryInfo info: tagNames)
    {
        handles.push_back(i);
        i++;
    }
    return handles;
}

/**
 * @brief Return the number of registered keys of a particular type
 *
 * This method is used by the StorageModule.
 * 
 * @param type the type of interest
 * @return int the number of unique keys
 */
int StorageRegistry::getNumKeys(storageTypes type)
{
    switch(type)
    {
    case INT:
        return intKeys.size();
        break;
    case FLOAT:
        return floatKeys.size();
        break;
    case BUFFER:
        return bufferKeys.size();
        break;
    }

    //Shouldn't happen
    throw RuntimeException("Unknown key registration type", RuntimeException::UNEXPECTED_ERROR);
}

/**
 * @brief return the number of registered tags
 *
 * This method is used by the StorageModule.
 * 
 * @return int the number of unique tag names
 */
int StorageRegistry::getNumTags()
{
    return tagNames.size();
}

/**
 * @brief Return the handle for the key that storage should be sorted by
 * 
 * This method is used by the StorageModule.
 * 
 * @return int the handle
 */
int StorageRegistry::getSortByKey()
{
    return sortByKeyHandle;
}

/**
 * @brief Return the data type for the key that storage should be sorted by
 * 
 * This method is used by the StorageModule.
 * 
 * @return StorageRegistry::storageTypes the data type
 */
StorageRegistry::storageTypes StorageRegistry::getSortByType()
{
    return sortByType;
}

/**
 * @brief Return the direction that storage should sort by (using the sort by key)
 *
 * This method is used by the StorageModule.
 * 
 * @return StorageRegistry::sortOrder the order
 */
StorageRegistry::sortOrder StorageRegistry::getSortByOrder()
{
    return sortByOrder;
}

/**
 * @brief Helper method to add a new key to the metadata if it's not already present, and updat metadata with
 * the provided access information
 *
 * @param keyList the list to add to
 * @param keyName the key name
 * @param access the type of access
 * @return int the handle to the key to be used for subsequent access
 */
int StorageRegistry::addIfNotPresent(vector<StorageRegistry::registryInfo>& keyList, string keyName, accessType access)
{
    bool found = false;
    size_t i;
    for(i=0; i<keyList.size(); i++)
    {
        if(keyName == keyList[i].name)
        {
            found = true;
            break;
        }
    }

    if(found)
    {
        if((READ_ONLY == access)||(READ_WRITE == access))
        {
            keyList[i].isRead = true;
        }
        if((WRITE_ONLY == access)||(READ_WRITE == access))
        {
            keyList[i].isWritten = true;
        }
        return i;
    }
    else
    {

        bool isRead = ((READ_ONLY == access)||(READ_WRITE == access));
        bool isWritten = ((WRITE_ONLY == access)||(READ_WRITE == access));

        keyList.push_back({keyName, isRead, isWritten});
        int index = keyList.size() - 1;
        return index;
    }
}
