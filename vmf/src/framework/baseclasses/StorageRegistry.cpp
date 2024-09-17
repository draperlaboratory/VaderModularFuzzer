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
#include "StorageRegistry.hpp"
#include "StorageKeyHelper.hpp"
#include "RuntimeException.hpp"
#include "Logging.hpp"

using namespace vmf;
using std::string;
using std::vector;

std::vector<StorageRegistry::storageTypes> StorageRegistry::storageTypeList = {StorageRegistry::INT, 
                                                                    StorageRegistry::UINT, 
                                                                    StorageRegistry::FLOAT, 
                                                                    StorageRegistry::BUFFER, 
                                                                    StorageRegistry::BUFFER_TEMP};

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
    readAllKeys         = false;
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

    for(storageTypes type: storageTypeList)
    {
        registryMap.insert(std::pair<storageTypes, vector<registryInfo>>(type, vector<registryInfo>()));
    }
}

/**
 * @brief Destroy the Storage Registry:: Storage Registry object
 *
 */
StorageRegistry::~StorageRegistry()
{
    registryMap.clear();
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
    else if("BUFFER_TEMP" == type)
    {
        enumVal = BUFFER_TEMP;
    }
    else if("UINT" == type)
    {
        enumVal = UINT;
    }
    else if("INT" != type)
    {
        LOG_ERROR << "storageType specified is not a valid enum value: " << type;
        throw RuntimeException ("Invalid storageType specified", RuntimeException::USAGE_ERROR);
    }
    return enumVal;
}

/**
 * @brief Helper method to convert a storage type enum to a string value
 * 
 * @param type 
 * @return std::string 
 */
std::string StorageRegistry::storageTypeToString(storageTypes type)
{
    switch(type)
    {
        case INT:
            return "INT";
            break;
        case UINT:
            return "UINT";
            break;
        case FLOAT:
            return "FLOAT";
            break;
        case BUFFER:
            return "BUFFER";
            break;
        case BUFFER_TEMP:
            return "BUFFER_TEMP";
            break;
        default:
            //This shouldn't be possible
            throw RuntimeException("Unknown storage type provided",RuntimeException::USAGE_ERROR);
            break;
    }
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
    //This should be an impossible error, but double check that the number of default int and float values
    //matches the number of keys
    if((registryMap[INT].size() != intDefaults.size())||
       (registryMap[UINT].size() != uintDefaults.size())||
       (registryMap[FLOAT].size() != floatDefaults.size()))
    {
        LOG_ERROR << "Programming Error -- the number of int, uint, or float keys does not match the number of default values";
        return false;
    }

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

    //Prior to validating keys, update the registration based on the readAllKeys parameter
    if(readAllKeys)
    {
        for(storageTypes type: storageTypeList)
        {
            setIsReadOnAllKeys(registryMap[type]);
        }
    }
    bool isValid = validateList(tagNames, "tag");
    for(storageTypes type: storageTypeList)
    {
        isValid = isValid && validateList(registryMap[type],storageTypeToString(type));
    }

    return isValid;
}

/**
 * @brief Helper method to set the isRead flag for all keys on the provided keyList
 * 
 * @param keyList the list of keys
 */
void StorageRegistry::setIsReadOnAllKeys(std::vector<registryInfo> keyList)
{
    int numKeys = keyList.size();
    for(int i=0; i<numKeys; i++)
    {
        keyList[i].isRead = true;
    }
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
    LOG_INFO << "StorageRegistry::Validating " << listName << " fields";

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
    bool wasNew = false;
    int typeMask = StorageKeyHelper::enumToType(type);
    int handle = addIfNotPresent(typeMask,registryMap[type],keyName,access,wasNew);

    if(wasNew)
    {
        if(INT == type)
        {
            intDefaults.push_back(0); //When unspecified, the default value is 0
        }
        else if(UINT == type)
        {
            uintDefaults.push_back(0); //When unspecified, the default value is 0
        }
        else if(FLOAT == type)
        {
            floatDefaults.push_back(0.0); //When unspecified, the default value is 0.0
        }
        //The other types do not support default values
    }

    return handle;

}

/**
 * @brief Register a key for a data field (with a default integer value)
 *
 * This version of the register key method registers a key of type INT with the specified default value.
 * 
 * @param keyName the unique string name of the field
 * @param access how the caller doing the registration will use the key
 * @param defaultValue the default value to use for the key
 * @return int the handle to use for subsequent access to the key (for getters and setters in the StorageEntry)
 */
int StorageRegistry::registerIntKey(std::string keyName, accessType access, int defaultValue)
{
    return registerWithDefault(keyName, access, StorageKeyHelper::INT_TYPE_MASK, registryMap[INT], intDefaults, defaultValue);
}

/**
 * @brief Register a key for a data field (with a default unsigned integer value)
 *
 * This version of the register key method registers a key of type UINT with the specified default value.
 * 
 * @param keyName the unique string name of the field
 * @param access how the caller doing the registration will use the key
 * @param defaultValue the default value to use for the key
 * @return int the handle to use for subsequent access to the key (for getters and setters in the StorageEntry)
 */
int StorageRegistry::registerUIntKey(std::string keyName, accessType access, unsigned int defaultValue)
{
    return registerWithDefault(keyName, access, StorageKeyHelper::UINT_TYPE_MASK, registryMap[UINT], uintDefaults, defaultValue);
}

/**
 * @brief Register a key for a data field (with a default float value)
 *
 * This version of the register key method registers a key of type FLOAT with the specified default value.
 * 
 * @param keyName the unique string name of the field
 * @param access how the caller doing the registration will use the key
 * @param defaultValue the default value to use for the key
 * @return int the handle to use for subsequent access to the key (for getters and setters in the StorageEntry)
 */
int StorageRegistry::registerFloatKey(std::string keyName, accessType access, float defaultValue)
{
    return registerWithDefault(keyName, access, StorageKeyHelper::FLOAT_TYPE_MASK, registryMap[FLOAT], floatDefaults, defaultValue);
}

/**
 * @brief Helper method to implement registerXXXKey methods
 * 
 * @param keyName the unique string name of the field
 * @param keyList the key list for this datatype
 * @param defaultList the default list for this datatype
 * @param defaultValue the default value to set
 * @return int the handle to use
 */
template <class T> int StorageRegistry::registerWithDefault(std::string keyName, accessType access, int typeMask, std::vector<registryInfo>& keyList, std::vector<T>& defaultList, T defaultValue)
{
    bool wasNew = false;
    int handle = addIfNotPresent(typeMask,keyList,keyName,access,wasNew);
    int index = StorageKeyHelper::getIndex(handle); //real underlying array index (without type mask)

    //Also add an entry to the defaults table
    if(wasNew)
    {
        //This was a new key, so set the default value
        keyList[index].hasDefault = true;
        defaultList.push_back(defaultValue);
    }
    else if(keyList[index].hasDefault)
    {
        //This is not a new entry, but there was already a default value set
        //So we need to make sure the default value specified here is the same
        if(defaultValue != defaultList[index])
        {
            LOG_ERROR << "Attempted to register two different default values for key " << keyName << " (" <<
                      defaultValue << " and " << defaultList[index] << ")";
            throw RuntimeException("Key was registered with two different default values", RuntimeException::CONFIGURATION_ERROR);
        }
    }
    else
    {
        //The key was previously registered with no default value specified, so now we will set one
        keyList[index].hasDefault = true;
        defaultList[index] = defaultValue;
    }

    return handle;
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
    bool wasNew;
    return addIfNotPresent(StorageKeyHelper::TAG_TYPE_MASK,tagNames,tagName,access,wasNew);
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
 * @brief Register for read-only access to all the keys in the storage registry
 * Note that because registration happens one module at a time, any module
 * that wants to use all of the keys must request the key handles
 * after registration is complete.  The key handles should be requested
 * directly from the StorageModule sometime after initialization is complete.
 * 
 * This capability is primarily useful for output modules that want to dump
 * data from storage somewhat mindlessly.
 * 
 * There is no capability to register to write all of the keys, as it would
 * be impossible to do so meaningfully without understanding the semantic intent
 * of each key.
 */
void StorageRegistry::registerToReadAllKeys()
{
    readAllKeys = true;
}

/**
 * @brief Returns the map of handles to registered tag names
 * The names are in a human readable form.
 * 
 * This method is used by the StorageModule to retrieve the tag names.  It should not be
 * called during registration, as it may return an incomplete list of tags.  Modules
 * that need the list of tags should retrieve them from storage after initialization is complete.
 * 
 * @return std::unordered_map<int,std::string> where the int key is the handle and the string is the name
 */
std::unordered_map<int,std::string> StorageRegistry::getTagNameMap()
{
    std::unordered_map<int,std::string> nameMap;
    for(registryInfo info: tagNames)
    {
        nameMap[info.handle] = info.name;
    }
    return nameMap;
}

/**
 * @brief Returns the map of handles to registered key names
 * The names are in a human readable form.
 * 
 * This method is used by the StorageModule to retrieve the key names.  It should not be
 * called during registration, as it may return an incomplete list of keys.  Modules
 * that need the list of keys should retrieve them from storage after initialization is complete.
 * 
 * @return std::unordered_map<int,std::string> where the int key is the handle and the string is the name
 */
std::unordered_map<int,std::string> StorageRegistry::getKeyNameMap()
{
    std::unordered_map<int,std::string> nameMap;
    for(storageTypes type: storageTypeList)
    {
        for(registryInfo info: registryMap[type])
        {
            nameMap[info.handle] = info.name;
        }
    }
    return nameMap;
}

/**
 * @brief Returns the list of all tag handles
 * These are returned in the order that the tags were registered in (so they can be
 * mapped to the list returned by getTagNameMap).
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
    return registryMap[type].size();
}

/**
 * @brief Helper method to return all the registered keys of a particular data type
 * 
 * @param type the type of interest
 * @return std::vector<int> the list of handles to the keys
 */
std::vector<int> StorageRegistry::getKeyHandles(storageTypes type)
{
    std::vector<int> handles;
   
    for(int i=0; i<(int)registryMap[type].size(); i++)
    {
        handles.push_back(registryMap[type][i].handle);
    }

    return handles;

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
 * @brief Returns the default values for the int keys
 * 
 * @return std::vector<int> 
 */
std::vector<int> StorageRegistry::getIntKeyDefaults()
{
    return intDefaults;
}

/**
 * @brief Returns the default values for the unsigned int keys
 * 
 * @return std::vector<unsigned int> 
 */
std::vector<unsigned int> StorageRegistry::getUIntKeyDefaults()
{
    return uintDefaults;
}


/**
 * @brief Returns the default values for the float keys
 * 
 * @return std::vector<float> 
 */
std::vector<float> StorageRegistry::getFloatKeyDefaults()
{
    return floatDefaults;
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
 * @brief Helper method to add a new key to the registry if it's not already present, and update the registry with
 * the provided access information
 *
 * @param typeMask the type mask to use on the handle to the key
 * @param keyList the list to add to
 * @param keyName the key name
 * @param access the type of access
 * @param[out] wasNew this is an output variable -- it is set to true if a new key was added and false if it already existed
 * @return int the handle to the key to be used for subsequent access, and also sets the wasNew variable value
 */
int StorageRegistry::addIfNotPresent(int typeMask, vector<StorageRegistry::registryInfo>& keyList, string keyName, accessType access, bool& wasNew)
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
        wasNew = false;
        return StorageKeyHelper::addTypeToIndex(i,typeMask);
    }
    else
    {

        bool isRead = ((READ_ONLY == access)||(READ_WRITE == access));
        bool isWritten = ((WRITE_ONLY == access)||(READ_WRITE == access));
        bool hasDefault = false;
        int index = keyList.size();

        wasNew = true;
        int handle = StorageKeyHelper::addTypeToIndex(index,typeMask);
        keyList.push_back({keyName, handle, isRead, isWritten, hasDefault});
        return handle;
    }
}
