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
#include "StorageEntry.hpp"
#include "StorageKeyHelper.hpp"
#include "Logging.hpp"
using namespace vmf;
unsigned long StorageEntry::uidCounter = 0;
int StorageEntry::pKey;
StorageRegistry::storageTypes StorageEntry::pKeyType = StorageRegistry::BUFFER;
int StorageEntry::maxInts = 0;
int StorageEntry::maxUInts = 0;
int StorageEntry::maxU64s = 0;
int StorageEntry::maxFloats = 0;
int StorageEntry::maxBuffers = 0;
int StorageEntry::maxTempBuffers = 0;
int StorageEntry::maxTags = 0;
int StorageEntry::maxIntsMetadata = 0;
int StorageEntry::maxUIntsMetadata = 0;
int StorageEntry::maxU64sMetadata = 0;
int StorageEntry::maxFloatsMetadata = 0;
int StorageEntry::maxBuffersMetadata = 0;
int StorageEntry::maxTempBuffersMetadata = 0;
std::vector<int> StorageEntry::intDefaults = {};
std::vector<unsigned int> StorageEntry::uintDefaults = {};
std::vector<unsigned long long> StorageEntry::u64Defaults = {};
std::vector<float> StorageEntry::floatDefaults = {};
std::vector<int> StorageEntry::intMetadataDefaults = {};
std::vector<unsigned int> StorageEntry::uintMetadataDefaults = {};
std::vector<unsigned long long> StorageEntry::u64MetadataDefaults = {};
std::vector<float> StorageEntry::floatMetadataDefaults = {};
std::unordered_map<int,std::string> StorageEntry::keyNameMap = {};
std::unordered_map<int,std::string> StorageEntry::metadataKeyNameMap = {};


/**
 * @brief Initialize the storage entry
 * This must be called once during initialization time to set the size of storage
 * 
 * @param registry the storage registry associated with the main part of storage
 */
void StorageEntry::init(StorageRegistry& registry)
{
    maxInts = registry.getNumKeys(StorageRegistry::INT);
    maxUInts = registry.getNumKeys(StorageRegistry::UINT);
    maxU64s = registry.getNumKeys(StorageRegistry::U64);
    maxFloats = registry.getNumKeys(StorageRegistry::FLOAT);
    maxBuffers = registry.getNumKeys(StorageRegistry::BUFFER);
    maxTempBuffers = registry.getNumKeys(StorageRegistry::BUFFER_TEMP);
    maxTags = registry.getNumTags();

    intDefaults = registry.getIntKeyDefaults();
    uintDefaults = registry.getUIntKeyDefaults();
    u64Defaults = registry.getU64KeyDefaults();
    floatDefaults = registry.getFloatKeyDefaults();

    pKey = registry.getSortByKey();
    pKeyType = registry.getSortByType();

    keyNameMap = registry.getKeyNameMap();
}
/**
 * @brief Initialize the metadata storage entry
 * This must be called once during initialization time to set the size of metadata
 * 
 * @param metadata the storage registry associated with the metadata entry
 */
void StorageEntry::initMetadata(StorageRegistry& metadata)
{
    maxIntsMetadata = metadata.getNumKeys(StorageRegistry::INT);
    maxUIntsMetadata = metadata.getNumKeys(StorageRegistry::UINT);
    maxU64sMetadata = metadata.getNumKeys(StorageRegistry::U64);
    maxFloatsMetadata = metadata.getNumKeys(StorageRegistry::FLOAT);
    maxBuffersMetadata = metadata.getNumKeys(StorageRegistry::BUFFER);
    maxTempBuffersMetadata = metadata.getNumKeys(StorageRegistry::BUFFER_TEMP);

    intMetadataDefaults = metadata.getIntKeyDefaults();
    uintMetadataDefaults = metadata.getUIntKeyDefaults();
    u64MetadataDefaults = metadata.getU64KeyDefaults();
    floatMetadataDefaults = metadata.getFloatKeyDefaults();

    metadataKeyNameMap = metadata.getKeyNameMap();
}

/**
 * @brief Construct a new Storage Entry object
 * Only StorageModules should directly construct StorageEntry objects.
 * All other modules should request new StorageEntries from the StorageModule.
 * 
 * StorageModules should typically only construct one metadata StorageEntry.
 * 
 * @param isMetadata true if this is a metadata object, false otherwise
 * @param isLocal true if this is a local storage entry object, false otherwise
 * @param listener the storage entry listener
 */
StorageEntry::StorageEntry(bool isMetadata, bool isLocal, StorageEntryListener* listener) : uid(uidCounter++)
{
    this->isMetadataEntry = isMetadata;
    this->isLocal = isLocal;
    int numInts = maxInts;
    int numUInts = maxUInts;
    int numU64s = maxU64s;
    int numFloats = maxFloats;
    int numBuffs = maxBuffers;
    int numTempBuffs = maxTempBuffers;
    int numTags = maxTags;
    if(isMetadata)
    {
        numInts = maxIntsMetadata;
        numUInts = maxUIntsMetadata;
        numU64s = maxU64sMetadata;
        numFloats = maxFloatsMetadata;
        numBuffs = maxBuffersMetadata;
        numTempBuffs = maxTempBuffersMetadata;
        numTags = 0; //metadata does not have tags
    }

    //Initialize int values to the specified default
    intValues.reserve(numInts);
    for(int i=0; i<numInts; i++)
    {
        if(!isMetadata)
        {
            intValues.push_back(intDefaults[i]);
        }
        else
        {
            intValues.push_back(intMetadataDefaults[i]);
        }

    }

    //Initialize uint values to the specified default
    uintValues.reserve(numUInts);
    for(int i=0; i<numUInts; i++)
    {
        if(!isMetadata)
        {
            uintValues.push_back(uintDefaults[i]);
        }
        else
        {
            uintValues.push_back(uintMetadataDefaults[i]);
        }

    }

    //Initialize u64 values to the specified default
    u64Values.reserve(numU64s);
    for(int i=0; i<numU64s; i++)
    {
        if(!isMetadata)
        {
            u64Values.push_back(u64Defaults[i]);
        }
        else
        {
            u64Values.push_back(u64MetadataDefaults[i]);
        }

    }

    //Initialize float values to the specified default
    floatValues.reserve(numFloats);
    for(int i=0; i<numFloats; i++)
    {
        if(!isMetadata)
        {
            floatValues.push_back(floatDefaults[i]);
        }
        else
        {
            floatValues.push_back(floatMetadataDefaults[i]);
        }
    }

    bufferValues.reserve(numBuffs);
    bufferSizes.reserve(numBuffs);

    //Initialize the buffer sizes to indicate that data is unallocated
    for(int i=0; i<numBuffs; i++)
    {
        bufferSizes.push_back(UNALLOCATED_BUFFER);
        bufferValues.push_back(nullptr);
    }

    tmpBufferValues.reserve(numTempBuffs);
    tmpBufferSizes.reserve(numTempBuffs);

    //Initialize the temp buffer sizes to indicate that data is unallocated
    for(int i=0; i<numTempBuffs; i++)
    {
        tmpBufferSizes.push_back(UNALLOCATED_BUFFER);
        tmpBufferValues.push_back(nullptr);
    }


    //Initialize the tag values to false
    tagValues.reserve(numTags);
    for(int i=0; i<numTags; i++)
    {
        tagValues.push_back(false);
    }

    this->listener = listener;
}

/**
 * @brief Destroy the Storage Entry:: Storage Entry object
 *
 */
StorageEntry::~StorageEntry()
{
    //Free the memory assocaited with any storage data buffers
    int numBuff = maxBuffers;
    if(isMetadataEntry)
    {
        numBuff = maxBuffersMetadata;
    }
    int numTempBuff = maxTempBuffers;
    if(isMetadataEntry)
    {
        numTempBuff = maxTempBuffersMetadata;
    }

    for(int i=0; i<numBuff; i++)
    {
        if(UNALLOCATED_BUFFER != bufferSizes[i])
        {
            free (bufferValues[i]);
        }
    }
    for(int i=0; i<numTempBuff; i++)
    {
        if(UNALLOCATED_BUFFER != tmpBufferSizes[i])
        {
            free (tmpBufferValues[i]);
        }
    }
}

/**
 * @brief Return the unique identifier (uid) of the storage object
 *
 * @return unsigned long the id
 */
unsigned long StorageEntry::getID() const
{
    return uid;
}

/**
 * @brief Indicates whether or not this is a local, temporary storage entry
 * 
 * @return true if this is a local entry
 * @return false otherwise
 */
bool StorageEntry::isLocalEntry() const
{
    return isLocal;
}

/**
 * @brief Equality operator for storage entries.  Comparison is based on the address of the entry.
 *
 * Note: this comparison is to determine whether or not the StorageEntry is the same object instance,
 * equality comparison on storageEntry values is not performed.
 * @param e the entry to compare to
 * @return true if they are equal
 * @return false otherwise
 */
bool StorageEntry::operator == ( const StorageEntry& e )
{
    //This is an identity based comparison (addresses are equal)
    return(this == &e);
}

/**
 * @brief Comparison function for storage entries.  
 * Compares based on the sortBy key value.  This will return true if the current
 * storage entry's primary key is < the primary key of e.
 * 
 * For example, if storage is configured with float FITNESS as the primary key,
 * then this will compare this entry's fitness value with that of e.
 *
 * @param e the storage entry to compare to
 * @return true if the current storage entry is < e
 * @throws RuntimeException if the sort by key type is of an invalid type
 */
bool StorageEntry::sortByValueIsLessThan( const StorageEntry& e )
{
    if(!isMetadataEntry){
        if(StorageRegistry::INT == pKeyType)
        {
            return (getIntValue(pKey) < e.getIntValue(pKey));
        }
        else if(StorageRegistry::UINT == pKeyType)
        {
            return (getUIntValue(pKey) < e.getUIntValue(pKey));
        }
        else if(StorageRegistry::U64 == pKeyType)
        {
            return (getU64Value(pKey) < e.getU64Value(pKey));
        }
        else if(StorageRegistry::FLOAT == pKeyType)
        {
            return (getFloatValue(pKey) < e.getFloatValue(pKey));
        }
        else //BUFFER
        {
            throw RuntimeException("Storage was configured with an invalid sort type (must be int, unsigned int, or float)",
                                RuntimeException::CONFIGURATION_ERROR);
        }
    } 
    else 
    {
        throw RuntimeException("MetadataEntries cannot be sorted",
                                RuntimeException::USAGE_ERROR);
    }
}

/**
 * @brief Helper method to check range and type validity for a handle, and return the valid index
 * 
 * @param handle the handle
 * @param expectedType the expected type (StorageKeyHelper type mask value)
 * @param isMetadata whether or not this is a metadata entry
 * @param entryMax the max value for regular entries
 * @param metaMax the max value for metadata entries
 * @returns the actual valid index to the underlying data structures
 * @throws RuntimeException if the handle is not valid
 */
int StorageEntry::getHandleIndex(int handle, int expectedType, bool isMetadata, int entryMax, int metaMax)
{
    int typeMask = StorageKeyHelper::getType(handle);
    if(expectedType != typeMask)
    {
        LOG_ERROR << "Key type was not correct when accessing storage -- was the wrong accessor method used?";
        LOG_ERROR << "This was for key name " << getHandleName(handle, isMetadata) << ", handle=" << handle;
        LOG_ERROR << "Expected a key of type " << StorageKeyHelper::typeToString(expectedType) << 
                     ", found a key of type " << StorageKeyHelper::typeToString(typeMask);
        throw RuntimeException("Attempt to access storage with a key of the wrong type", RuntimeException::USAGE_ERROR);
    }

    int index = StorageKeyHelper::getIndex(handle);
    int max = entryMax;
    if(isMetadata)
    {
        max = metaMax;
    }

    if(!((index >= 0) && (index < max)))
    {
        LOG_ERROR << "Key was invalid or corrupt when accessing storage -- was the wrong key used?";
        LOG_ERROR << "This was for key name " << getHandleName(handle, isMetadata) << ", handle=" << handle;
        LOG_ERROR << "Out of range key of type " << StorageKeyHelper::typeToString(typeMask);
        throw RuntimeException("Attempt to access storage with an invalid key",
                               RuntimeException::INDEX_OUT_OF_RANGE);
    }
    return index;
}

/**
 * @brief Helper method to check range and type validity for a buffer handle, and return the valid index
 * 
 * This method also sets the output variable typeIsTmpBuffer if the buffer is a temporary buffer.
 * 
 * @param handle the handle
 * @param isMetadata whether or not this is a metadata entry
 * @param[out] typeIsTmpBuffer set to true if this is a temorary buffer, false otherwise
 * @returns the actual valid index to the underlying data structures
 * @throws RuntimeException if the handle is not valid
 */
int StorageEntry::getBufferHandleIndex(int handle, int isMetadata, bool& typeIsTmpBuffer)
{
    //Check that the type of BUFFER or BUFFER_TEMP
    int typeMask = StorageKeyHelper::getType(handle);
    int entryMax = 0;
    int metaMax = 0;
    if(StorageKeyHelper::BUFFER_TYPE_MASK == typeMask)
    {
        typeIsTmpBuffer = false;
        entryMax = maxBuffers;
        metaMax = maxBuffersMetadata;
    }
    else if(StorageKeyHelper::BUFFER_TEMP_TYPE_MASK == typeMask)
    {
        typeIsTmpBuffer = true;
        entryMax = maxTempBuffers;
        metaMax = maxTempBuffersMetadata;
    }
    else
    {
        LOG_ERROR << "Wrong type of key was provided, key name " << getHandleName(handle, isMetadata) << ", handle=" << handle;
        LOG_ERROR << "Expected BUFFER or BUFFER_TEMP key type, but found key of type " << StorageKeyHelper::typeToString(typeMask);
        throw RuntimeException("Attempt to access storage with a key of the wrong type", RuntimeException::USAGE_ERROR);
    }

    //Check that the index is in a valid range
    int index = StorageKeyHelper::getIndex(handle);
    int max = entryMax;
    if(isMetadata)
    {
        max = metaMax;
    }

    if(!((index >= 0) && (index < max)))
    {
        LOG_ERROR << "Key was invalid or corrupt when accessing storage buffer -- was the wrong key used?";
        LOG_ERROR << "This was for key name " << getHandleName(handle, isMetadata) << ", handle=" << handle;
        LOG_ERROR << "Out of range key of type " << StorageKeyHelper::typeToString(typeMask);
        throw RuntimeException("Attempt to access storage with an invalid key",
                               RuntimeException::INDEX_OUT_OF_RANGE);
    }
    return index;
}

/**
 * @brief Helper method to get the name associated with a handle
 * 
 * @param handle the handle to lookup
 * @param isMetadata whether or not this is a metadata handle
 * @return std::string the name associated with the handle, or "UNKNOWN_KEY" or "UNKNOWN_METADATA_KEY"
 * if it's not found (the latter for metadata keys)
 */
std::string StorageEntry::getHandleName(int handle, bool isMetadata)
{
    std::string keyName;

    if(isMetadata)
    {
        std::unordered_map<int,std::string>::const_iterator found = metadataKeyNameMap.find(handle);
        if ( found == metadataKeyNameMap.end() )
            keyName = "UNKNOWN_METADATA_KEY";
        else
            keyName = found->second;
    }
    else
    {
        std::unordered_map<int,std::string>::const_iterator found = keyNameMap.find(handle);
        if ( found == keyNameMap.end() )
            keyName = "UNKNOWN_KEY";
        else
            keyName = found->second;
    }

    return keyName;
}

/**
 * @brief Sets an integer value.  Throws an exception if the handle is invalid.
 *
 * @param handle the handle to the key
 * @param value the value to set
 */
void StorageEntry::setValue(int handle, int value)
{
    int key = getHandleIndex(handle, StorageKeyHelper::INT_TYPE_MASK, isMetadataEntry, maxInts, maxIntsMetadata);
    intValues[key] = value;

    //Notify storage if the primary key has been modified
    //(for entries that are neither local, nor metadata only)
    if(!isMetadataEntry && !isLocal)
    {
        if((StorageRegistry::INT == pKeyType) && (handle == pKey))
        {
            listener->notifyPrimaryKeyUpdated(this);
        }
    }
}

/**
 * @brief Sets an unsigned integer value.  Throws an exception if the handle is invalid.
 *
 * @param handle the handle to the key
 * @param value the value to set
 */
void StorageEntry::setValue(int handle, unsigned int value)
{
    int key = getHandleIndex(handle, StorageKeyHelper::UINT_TYPE_MASK, isMetadataEntry, maxUInts, maxUIntsMetadata);
    uintValues[key] = value;

    //Notify storage if the primary key has been modified
    //(for entries that are neither local, nor metadata only)
    if(!isMetadataEntry && !isLocal)
    {
        if((StorageRegistry::UINT == pKeyType) && (handle == pKey))
        {
            listener->notifyPrimaryKeyUpdated(this);
        }
    }
}

/**
 * @brief Sets an unsigned long long value.  Throws an exception if the handle is invalid.
 *
 * @param handle the handle to the key
 * @param value the value to set
 */
void StorageEntry::setValue(int handle, unsigned long long value)
{
    int key = getHandleIndex(handle, StorageKeyHelper::U64_TYPE_MASK, isMetadataEntry, maxU64s, maxU64sMetadata);
    u64Values[key] = value;

    //Notify storage if the primary key has been modified
    //(for entries that are neither local, nor metadata only)
    if(!isMetadataEntry && !isLocal)
    {
        if((StorageRegistry::U64 == pKeyType) && (handle == pKey))
        {
            listener->notifyPrimaryKeyUpdated(this);
        }
    }
}

/**
 * @brief Increments an integer value.  Throws an exception if the key is invalid.
 * 
 * This is a convenience method for metadata that is used as a counter, as the value
 * can be incremented by 1 in a single call.
 * 
 * @param handle the handle to the key
 * @returns the update value (after incrementing by 1)
 */
int StorageEntry::incrementIntValue(int handle)
{
    int key = getHandleIndex(handle, StorageKeyHelper::INT_TYPE_MASK, isMetadataEntry, maxInts, maxIntsMetadata);
    intValues[key]++;

    //It seems unlikely that this method would ever be called on the primary
    //key, but this is included for completeness, just in case
    //Notify storage if the primary key has been modified
    //(for entries that are neither local, nor metadata only)
    if(!isMetadataEntry && !isLocal)
    {
        if((StorageRegistry::INT == pKeyType) && (handle == pKey))
        {
            listener->notifyPrimaryKeyUpdated(this);
        }
    }

    return intValues[key];
}

/**
 * @brief Increments an unsigned integer value.  Throws an exception if the handle is invalid.
 * 
 * This is a convenience method for metadata that is used as a counter, as the value
 * can be incremented by 1 in a single call.
 * 
 * @param handle the handle to the key
 * @returns the update value (after incrementing by 1)
 */
unsigned int StorageEntry::incrementUIntValue(int handle)
{
    int key = getHandleIndex(handle, StorageKeyHelper::UINT_TYPE_MASK, isMetadataEntry, maxUInts, maxUIntsMetadata);
    uintValues[key]++;

    //It seems unlikely that this method would ever be called on the primary
    //key, but this is included for completeness, just in case
    //Notify storage if the primary key has been modified
    //(for entries that are neither local, nor metadata only)
    if(!isMetadataEntry && !isLocal)
    {
        if((StorageRegistry::UINT == pKeyType) && (handle == pKey))
        {
            listener->notifyPrimaryKeyUpdated(this);
        }
    }

    return uintValues[key];
}

/**
 * @brief Increments an unsigned long long value.  Throws an exception if the handle is invalid.
 * 
 * This is a convenience method for metadata that is used as a counter, as the value
 * can be incremented by 1 in a single call.
 * 
 * @param handle the handle to the key
 * @returns the update value (after incrementing by 1)
 */
unsigned long long StorageEntry::incrementU64Value(int handle)
{
    int key = getHandleIndex(handle, StorageKeyHelper::U64_TYPE_MASK, isMetadataEntry, maxU64s, maxU64sMetadata);
    u64Values[key]++;

    //It seems unlikely that this method would ever be called on the primary
    //key, but this is included for completeness, just in case
    //Notify storage if the primary key has been modified
    //(for entries that are neither local, nor metadata only)
    if(!isMetadataEntry && !isLocal)
    {
        if((StorageRegistry::U64 == pKeyType) && (handle == pKey))
        {
            listener->notifyPrimaryKeyUpdated(this);
        }
    }

    return u64Values[key];
}

/**
 * @brief Sets a float value.  Throws an exception if the handle is invalid.
 *
 * @param handle the handle to the key
 * @param value the value to set
 */
void StorageEntry::setValue(int handle, float value)
{
    int key = getHandleIndex(handle, StorageKeyHelper::FLOAT_TYPE_MASK, isMetadataEntry, maxFloats, maxFloatsMetadata);
    floatValues[key] = value;

    //Notify storage if the primary key has been modified
    //(for entries that are neither local, nor metadata only)
    if(!isMetadataEntry && !isLocal)
    {
        if((StorageRegistry::FLOAT == pKeyType) && (handle == pKey))
        {
            listener->notifyPrimaryKeyUpdated(this);
        }
    }
}


/**
 * @brief Gets an int value.  Throws an exception if the key is invalid.
 *
 * @param handle the handle to the key
 * @return the int value associated with the key
 */
int StorageEntry::getIntValue(int handle) const
{
    int key = getHandleIndex(handle, StorageKeyHelper::INT_TYPE_MASK, isMetadataEntry, maxInts, maxIntsMetadata);
    return intValues[key];
}

/**
 * @brief Gets an unsigned int value.  Throws an exception if the key is invalid.
 *
 * @param handle the handle to the key
 * @return the unsigned int value associated with the key
 */
unsigned int StorageEntry::getUIntValue(int handle) const
{
    int key = getHandleIndex(handle, StorageKeyHelper::UINT_TYPE_MASK, isMetadataEntry, maxUInts, maxUIntsMetadata);
    return uintValues[key];
}

/**
 * @brief Gets an unsigned long long value.  Throws an exception if the key is invalid.
 *
 * @param handle the handle to the key
 * @return the unsigned long long value associated with the key
 */
unsigned long long StorageEntry::getU64Value(int handle) const
{
    int key = getHandleIndex(handle, StorageKeyHelper::U64_TYPE_MASK, isMetadataEntry, maxU64s, maxU64sMetadata);
    return u64Values[key];
}

/**
 * @brief Gets a float value.  Throws an exception if the handle is invalid.
 *
 * @param handle the handle to the key
 * @return the float value associated with the key
 */
float StorageEntry::getFloatValue(int handle) const
{
    int key = getHandleIndex(handle, StorageKeyHelper::FLOAT_TYPE_MASK, isMetadataEntry, maxFloats, maxFloatsMetadata);
    return floatValues[key];

}

/**
 * @brief Allocate a data buffer in this storage entry.  Throws an exception if the handle or size are invalid.
 *
 * Only one call to allocateBuffer is allowed per key.  Attempts to reallocate will results in an exception.
 *
 * @param handle the handle to the key
 * @param size the size that should be allocated in the buffer
 * @return char* a pointer to the newly allocated buffer
 * @throws RuntimeException if the key or size are invalid, or if there is an attempt to re-allocate the buffer
 */
char* StorageEntry::allocateBuffer(int handle, int size)
{
    char* buff = nullptr;
    bool typeIsTmpBuffer = false;
    int key = getBufferHandleIndex(handle, isMetadataEntry, typeIsTmpBuffer);
    //Check that size is valid
    if(size <= 0)
    {
        throw RuntimeException("Attempt to allocate StorageEntry buffer with size <=0",
                               RuntimeException::USAGE_ERROR);
    }

    if(typeIsTmpBuffer)
    {
        //Allocate the buffer it is has not been allocated previously
        if(UNALLOCATED_BUFFER == tmpBufferSizes[key])
        {
            tmpBufferSizes[key]  = size;       
            tmpBufferValues[key] = (char*) malloc(size);

            buff = tmpBufferValues[key];
        }
        else
        {
            //Buffer is being allocated with a new size
            throw RuntimeException("Attempt to allocate StorageEntry temp buffer when it already contains data",
                                RuntimeException::USAGE_ERROR);
        }
    }
    else
    {
        //Allocate the buffer it is has not been allocated previously
        if(UNALLOCATED_BUFFER == bufferSizes[key])
        {
            bufferSizes[key]  = size;       
            bufferValues[key] = (char*) malloc(size);

            buff = bufferValues[key];
        }
        else
        {
            //Buffer is being allocated with a new size
            throw RuntimeException("Attempt to allocate StorageEntry buffer when it already contains data",
                                RuntimeException::USAGE_ERROR);
        }
    }

    //If the buffer has been allocated on this pass through the fuzzing loop, then we know
    //someone has likely written to the data on this pass through the fuzzing loop.
    //No one can write to temp data buffers without allocate being called, as there is by
    //definition no persistent data in these buffers.
    listener->notifyTempBufferSet(this,isMetadataEntry);

    return buff;
}

/**
 * @brief Allocate a data buffer in this storage entry, and initialize it with the provided value
 *
 * Only one call to allocateBuffer is allowed per key.  Attempts to reallocate will results in an exception.
 * The buffer will be initialized by copying size bytes from the provided srcBuffer.
 *
 * @param handle the handle to the key key
 * @param size the size that should be allocated in the buffer (and copied from the src buffer)
 * @param srcBuffer the src buffer that should be used to initialize the buffer
 * @return char* a pointer to the newly allocated buffer
 * @throws RuntimeException if the key or size are invalid, or if there is an attempt to re-allocate the buffer
 */
char* StorageEntry::allocateAndCopyBuffer(int handle, int size, char* srcBuffer)
{
    char* newBuff = allocateBuffer(handle,size);
    memcpy((void*)newBuff, (void*)srcBuffer, size);
    return newBuff;
}

/**
 * @brief Allocate a data buffer in this storage entry, and initialize it with the provided value
 *
 * Only one call to allocateBuffer is allowed per key.  Attempts to reallocate will results in an exception.
 * The buffer will be initialized by copying the data value from the provided srcEntry.
 *
 * @param handle the handle to the key
 * @param srcEntry the src entry from which the data should be copied
 * @return char* a pointer to the newly allocated buffer
 * @throws RuntimeException if the key is invalid, there is no such buffer in the srcEntry, or if there is an attempt to re-allocate the buffer
 */
char* StorageEntry::allocateAndCopyBuffer(int handle, StorageEntry* srcEntry)
{
    int size = srcEntry->getBufferSize(handle);
    if(size <= 0)
    {
        throw RuntimeException("Cannot copy from srcEntry, because the entry does not contain any data for this key", 
                                RuntimeException::OTHER);
    }

    char* srcBuffer = srcEntry->getBufferPointer(handle);
    char* newBuff = allocateBuffer(handle,size);
    memcpy((void*)newBuff, (void*)srcBuffer, size);

    return newBuff;
}

/**
 * @brief Clear a buffer in this storage entry
 * After this call, the buffer will return to the unallocated state (size of -1).
 * This method must be used with care, as it is deleting data that other modules might
 * want to use.  Safe usages of this method include:
 * - Clearing a buffer and then immediately re-allocating it with new data
 * - In specific situations where temporary data is only used by one module, filling a temporary 
 * buffer and then immediately clearing it (this should only be done if there are otherwise memory
 * usage concerns, as temporary buffer data will be cleared automatically by the framework on each
 * pass through the fuzzing loop)
 * 
 * @param handle the handle to clear
 * @throws RuntimeException if the handle is invalid, or not a buffer handle
 */
void StorageEntry::clearBuffer(int handle)
{
    bool typeIsTmpBuffer = false;
    int key = getBufferHandleIndex(handle, isMetadataEntry, typeIsTmpBuffer);
    if(typeIsTmpBuffer)
    {
        if(tmpBufferSizes[key]!=UNALLOCATED_BUFFER)
        {
            free (tmpBufferValues[key]);
            tmpBufferSizes[key] = UNALLOCATED_BUFFER;
        }
    }
    else
    {
        if(bufferSizes[key]!=UNALLOCATED_BUFFER)
        {
            free (bufferValues[key]);
            bufferSizes[key] = UNALLOCATED_BUFFER;
        }
    }
}

/**
 * @brief Helper method to check if this StorageEntry contains any data in the specified buffer
 * 
 * If the buffer has not yet been allocated, this method will return false.  If it has been 
 * allocated, this method will return true.
 * 
 * @param handle the handle to the data field of interest
 * @return true if the field has been allocated
 * @return false otherwise
 * @throws RuntimeException if this is not a valid buffer key
 */
bool StorageEntry::hasBuffer(int handle) const
{
    bool hasData = false;
    bool typeIsTmpBuffer = false;
    int key = getBufferHandleIndex(handle, isMetadataEntry, typeIsTmpBuffer);
    
    if(!typeIsTmpBuffer)
    {
        if(UNALLOCATED_BUFFER != bufferSizes[key])
        {
            hasData = true;
        }
    }
    else
    {
        if(UNALLOCATED_BUFFER != tmpBufferSizes[key])
        {
            hasData = true;
        }
    }

    return hasData;
}

/**
 * @brief Get the size of a data buffer
 *
 * @param handle the handle to the key
 * @return int the size (this will equal -1 if the buffer has not been allocated yet)
 */
int StorageEntry::getBufferSize(int handle) const
{
    bool typeIsTmpBuffer = false;
    int key = getBufferHandleIndex(handle, isMetadataEntry, typeIsTmpBuffer);    
    
    int size = 0;
    if(!typeIsTmpBuffer)
    {
        size = bufferSizes[key];
    }
    else
    {
        size = tmpBufferSizes[key];
    }
    return size;
}

/**
 * @brief Get the pointer to the buffer.  Throws an exception if the buffer has not been allocated yet.
 *
 * @param handle the handle to the key
 * @return char* the pointer to the buffer
 */
char* StorageEntry::getBufferPointer(int handle) const
{
    bool typeIsTmpBuffer = false;
    int key = getBufferHandleIndex(handle, isMetadataEntry, typeIsTmpBuffer);  

    if(!typeIsTmpBuffer)
    {
        if(bufferSizes[key] != UNALLOCATED_BUFFER)
        {
            return bufferValues[key];
        }
        else
        {
            throw RuntimeException("Attempt to access unallocated StorageEntry buffer",
                                RuntimeException::USAGE_ERROR);
        }

    }
    else
    {
        if(tmpBufferSizes[key] != UNALLOCATED_BUFFER)
        {
            return tmpBufferValues[key];
        }
        else
        {
            throw RuntimeException("Attempt to access unallocated StorageEntry temp buffer",
                                RuntimeException::USAGE_ERROR);
        }
    }
        

}

/**
 * @brief Tag this entry as having a particular attribute
 *
 * The tag must have been previously registed with the StorageRegistry.  This method
 * cannot be called on the metadata storage entry (if it is, an exception will be thrown).
 *
 * @param tagHandle tag handle (as returned from a call to StorageRegistry.registerTag)
 */
void StorageEntry::addTag(int tagHandle)
{
    if(isMetadataEntry)
    {
        throw RuntimeException("Tags cannot be set on metadata", RuntimeException::USAGE_ERROR);
    }

    int tagId = getHandleIndex(tagHandle, StorageKeyHelper::TAG_TYPE_MASK, isMetadataEntry, maxTags, 0);
    
    //Don't bother notifying storage if the tag value isn't actually changing
    //Also don't notify storage if this is a local entry (storage should never be notified in this case)
    if(false == tagValues[tagId])
    {
        tagValues[tagId] = true;
        if(!isLocal)
        {
            listener->notifyTagSet(this,tagId);
        }
        
    }
}

/**
 * @brief Remove a tag from this entry
 * 
 * This removes a tag from a previously tagged entry.  This method
 * cannot be called on the metadata storage entry (if it is, an exception will be thrown).
 * 
 * @param tagHandle the tag handle (as returned from a call to StorageRegistry.registerTag)
 */
void StorageEntry::removeTag(int tagHandle)
{
    if(isMetadataEntry)
    {
        throw RuntimeException( "Tags cannot be set on metadata", RuntimeException::USAGE_ERROR);
    }

    int tagId = getHandleIndex(tagHandle, StorageKeyHelper::TAG_TYPE_MASK, isMetadataEntry, maxTags, 0);
    

    //Don't bother notifying storage if the tag value isn't actually changing
    //Also don't notify storage if this is a local entry (storage should never be notified in this case)
    if(true == tagValues[tagId])
    {
        tagValues[tagId] = false;
        if(!isLocal)
        {
            listener->notifyTagRemoved(this,tagId);
        }
    }
}

/** 
 * @brief Check if this entry has a particular tag.
 * 
 * This method cannot be called on the metadata storage entry (if it is, an exception will be thrown).
 * 
 * @param tagHandle the tag handle (as returned from a call to StorageRegistry.registerTag)
 * @returns true if the entry has the tag, and false otherwise
 */
bool StorageEntry::hasTag(int tagHandle)
{
    if(isMetadataEntry)
    {
        throw RuntimeException( "Metadata does not have tags", RuntimeException::USAGE_ERROR);
    }

    int tagId = getHandleIndex(tagHandle, StorageKeyHelper::TAG_TYPE_MASK, isMetadataEntry, maxTags, 0);
    

    return tagValues[tagId];
}

/**
 * @brief Return all the tags for this storage entry
 * This is returned as a list of tag handles.  This method cannot be called
 * on the metadata storage entry (if it is, an exception will be thrown).
 * 
 * @return std::vector<int> the list of tag handles
 */
std::vector<int> StorageEntry::getTagList()
{
    if(isMetadataEntry)
    {
        throw RuntimeException( "Metadata does not have tags", RuntimeException::USAGE_ERROR);
    }

    std::vector<int> tagList;
    for(int i = 0; i<maxTags; i++)
    {
        if(tagValues[i])
        {
            int handle = StorageKeyHelper::addTypeToIndex(i,StorageKeyHelper::TAG_TYPE_MASK);
            tagList.push_back(handle);
        }
    } 
    return tagList;
}
