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
#include "StorageEntry.hpp"
using namespace vmf;
unsigned long StorageEntry::uidCounter = 0;
int StorageEntry::pKey;
StorageRegistry::storageTypes StorageEntry::pKeyType = StorageRegistry::BUFFER;
int StorageEntry::maxInts = 0;
int StorageEntry::maxFloats = 0;
int StorageEntry::maxBuffers = 0;
int StorageEntry::maxTags = 0;
int StorageEntry::maxIntsMetadata = 0;
int StorageEntry::maxFloatsMetadata = 0;
int StorageEntry::maxBuffersMetadata = 0;
std::vector<int> StorageEntry::intDefaults = {};
std::vector<float> StorageEntry::floatDefaults = {};
std::vector<int> StorageEntry::intMetadataDefaults = {};
std::vector<float> StorageEntry::floatMetadataDefaults = {};

/**
 * @brief Initialize the storage entry
 * This must be called once during initialization time to set the size of storage
 * 
 * @param registry the storage registry associated with the main part of storage
 */
void StorageEntry::init(StorageRegistry& registry)
{
    maxInts = registry.getNumKeys(StorageRegistry::INT);
    maxFloats = registry.getNumKeys(StorageRegistry::FLOAT);
    maxBuffers = registry.getNumKeys(StorageRegistry::BUFFER);
    maxTags = registry.getNumTags();

    intDefaults = registry.getIntKeyDefaults();
    floatDefaults = registry.getFloatKeyDefaults();

    pKey = registry.getSortByKey();
    pKeyType = registry.getSortByType();
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
    maxFloatsMetadata = metadata.getNumKeys(StorageRegistry::FLOAT);
    maxBuffersMetadata = metadata.getNumKeys(StorageRegistry::BUFFER);

    intMetadataDefaults = metadata.getIntKeyDefaults();
    floatMetadataDefaults = metadata.getFloatKeyDefaults();
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
    int numFloats = maxFloats;
    int numBuffs = maxBuffers;
    int numTags = maxTags;
    if(isMetadata)
    {
        numInts = maxIntsMetadata;
        numFloats = maxFloatsMetadata;
        numBuffs = maxBuffersMetadata;
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
        bufferValues.push_back(0);
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
    for(int i=0; i<numBuff; i++)
    {
        if(UNALLOCATED_BUFFER != bufferSizes[i])
        {
            free (bufferValues[i]);
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
        else if(StorageRegistry::FLOAT == pKeyType)
        {
            return (getFloatValue(pKey) < e.getFloatValue(pKey));
        }
        else //BUFFER
        {
            throw RuntimeException("Storage was configured with an invalid sort type (must be int or float)",
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
 * @brief Checks that the provided key is valid (>= 0 and < max)
 *
 * @param key the key
 * @param max the value the key must be less than to be valid
 * @return true if the key is valid
 * @throws RuntimeException if the key is invalid
 */
bool StorageEntry::checkThatRangeIsValid(int key, int max)
{
    if((key >= 0) && (key < max))
    {
        return true;
    }
    else
    {
        throw RuntimeException("Attempt to access storage with an invalid key",
                               RuntimeException::INDEX_OUT_OF_RANGE);
    }
}

/**
 * @brief Sets an integer value.  Throws an exception if the key is invalid.
 *
 * @param key the key
 * @param value the value to set
 */
void StorageEntry::setValue(int key, int value)
{
    if(isMetadataEntry)
        checkThatRangeIsValid(key,maxIntsMetadata);
    else
        checkThatRangeIsValid(key,maxInts);
    intValues[key] = value;

    //Notify storage if the primary key has been modified
    //(for entries that are neither local, nor metadata only)
    if(!isMetadataEntry && !isLocal)
    {
        if((StorageRegistry::INT == pKeyType) && (key == pKey))
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
 * @param key the key
 * @returns the update value (after incrementing by 1)
 */
int StorageEntry::incrementIntValue(int key)
{
    if(isMetadataEntry)
        checkThatRangeIsValid(key,maxIntsMetadata);
    else
        checkThatRangeIsValid(key,maxInts);
    intValues[key]++;

    //It seems unlikely that this method would ever be called on the primary
    //key, but this is included for completeness, just in case
    //Notify storage if the primary key has been modified
    //(for entries that are neither local, nor metadata only)
    if(!isMetadataEntry && !isLocal)
    {
        if((StorageRegistry::INT == pKeyType) && (key == pKey))
        {
            listener->notifyPrimaryKeyUpdated(this);
        }
    }

    return intValues[key];
}

/**
 * @brief Sets a float value.  Throws an exception if the key is invalid.
 *
 * @param key the key
 * @param value the value to set
 */
void StorageEntry::setValue(int key, float value)
{
    if(isMetadataEntry)
        checkThatRangeIsValid(key,maxFloatsMetadata);
    else
        checkThatRangeIsValid(key,maxFloats);
    
    floatValues[key] = value;

    //Notify storage if the primary key has been modified
    //(for entries that are neither local, nor metadata only)
    if(!isMetadataEntry && !isLocal)
    {
        if((StorageRegistry::FLOAT == pKeyType) && (key == pKey))
        {
            listener->notifyPrimaryKeyUpdated(this);
        }
    }
}


/**
 * @brief Gets an int value.  Throws an exception if the key is invalid.
 *
 * @param key the key
 * @return the int value associated with the key
 */
int StorageEntry::getIntValue(int key) const
{
    if(isMetadataEntry)
        checkThatRangeIsValid(key,maxIntsMetadata);
    else
        checkThatRangeIsValid(key,maxInts);
    return intValues[key];
}

/**
 * @brief Gets a float value.  Throws an exception if the key is invalid.
 *
 * @param key the key
 * @return the float value associated with the key
 */
float StorageEntry::getFloatValue(int key) const
{
    if(isMetadataEntry)
        checkThatRangeIsValid(key,maxFloatsMetadata);
    else
        checkThatRangeIsValid(key,maxFloats);
    return floatValues[key];

}

/**
 * @brief Allocate a data buffer in this storage entry.  Throws an exception if the key or size are invalid.
 *
 * Only one call to allocateBuffer is allowed per key.  Attempts to reallocate will results in an exception.
 *
 * @param key the key
 * @param size the size that should be allocated in the buffer
 * @return char* a pointer to the newly allocated buffer
 * @throws RuntimeException if the key or size are invalid, or if there is an attempt to re-allocate the buffer
 */
char* StorageEntry::allocateBuffer(int key, int size)
{
    if(isMetadataEntry)
        checkThatRangeIsValid(key,maxBuffersMetadata);
    else
        checkThatRangeIsValid(key,maxBuffers);

    //Check that size is valid
    if(size <= 0)
    {
        throw RuntimeException("Attempt to allocate StorageEntry buffer with size <=0",
                               RuntimeException::USAGE_ERROR);
    }

    //Allocate the buffer it is has not been allocated previously
    if(UNALLOCATED_BUFFER == bufferSizes[key])
    {
        bufferSizes[key]  = size;       
        bufferValues[key] = (char*) malloc(size);

        return bufferValues[key];
    }
    else
    {
        //Buffer is being allocated with a new size
        throw RuntimeException("Attempt to allocate StorageEntry buffer more than once",
                               RuntimeException::USAGE_ERROR);
    }
}

/**
 * @brief Allocate a data buffer in this storage entry, and initialize it with the provided value
 *
 * Only one call to allocateBuffer is allowed per key.  Attempts to reallocate will results in an exception.
 * The buffer will be initialized by copying size bytes from the provided srcBuffer.
 *
 * @param key the key
 * @param size the size that should be allocated in the buffer (and copied from the src buffer)
 * @param srcBuffer the src buffer that should be used to initialize the buffer
 * @return char* a pointer to the newly allocated buffer
 * @throws RuntimeException if the key or size are invalid, or if there is an attempt to re-allocate the buffer
 */
char* StorageEntry::allocateAndCopyBuffer(int key, int size, char* srcBuffer)
{
    char* newBuff = allocateBuffer(key,size);
    memcpy((void*)newBuff, (void*)srcBuffer, size);
    return newBuff;
}

/**
 * @brief Allocate a data buffer in this storage entry, and initialize it with the provided value
 *
 * Only one call to allocateBuffer is allowed per key.  Attempts to reallocate will results in an exception.
 * The buffer will be initialized by copying the data value from the provided srcEntry.
 *
 * @param key the key
 * @param srcEntry the src entry from which the data should be copied
 * @return char* a pointer to the newly allocated buffer
 * @throws RuntimeException if the key is invalid, there is no such buffer in the srcEntry, or if there is an attempt to re-allocate the buffer
 */
char* StorageEntry::allocateAndCopyBuffer(int key, StorageEntry* srcEntry)
{
    int size = srcEntry->getBufferSize(key);
    if(size <= 0)
    {
        throw RuntimeException("Cannot copy from srcEntry, because the entry does not contain any data for this key", 
                                RuntimeException::OTHER);
    }

    char* srcBuffer = srcEntry->getBufferPointer(key);
    char* newBuff = allocateBuffer(key,size);
    memcpy((void*)newBuff, (void*)srcBuffer, size);

    return newBuff;
}

/**
 * @brief Helper method to check if this StorageEntry contains any data in the specified buffer
 * 
 * If the buffer has not yet been allocated, this method will return false.  If it has been 
 * allocated, this method will return true.
 * 
 * @param key the handle to the data field of interest
 * @return true if the field has been allocated
 * @return false otherwise
 * @throws RuntimeException if this is not a valid buffer key
 */
bool StorageEntry::hasBuffer(int key) const
{
    bool hasData = false;

    if(isMetadataEntry)
        checkThatRangeIsValid(key,maxBuffersMetadata);
    else
        checkThatRangeIsValid(key,maxBuffers);

    if(UNALLOCATED_BUFFER != bufferSizes[key])
    {
        hasData = true;
    }

    return hasData;
}

/**
 * @brief Get the size of a data buffer
 *
 * @param key the key
 * @return int the size (this will equal -1 if the buffer has not been allocated yet)
 */
int StorageEntry::getBufferSize(int key) const
{
    if(isMetadataEntry)
        checkThatRangeIsValid(key,maxBuffersMetadata);
    else
        checkThatRangeIsValid(key,maxBuffers);

    return bufferSizes[key];
}

/**
 * @brief Get the pointer to the buffer.  Throws an exception if the buffer has not been allocated yet.
 *
 * @param key the key
 * @return char* the pointer to the buffer
 */
char* StorageEntry::getBufferPointer(int key) const
{
    if(isMetadataEntry)
        checkThatRangeIsValid(key,maxBuffersMetadata);
    else
        checkThatRangeIsValid(key,maxBuffers);
        
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

/**
 * @brief Tag this entry as having a particular attribute
 *
 * The tag must have been previously registed with the StorageRegistry.  This method
 * cannot be called on the metadata storage entry (if it is, an exception will be thrown).
 *
 * @param tagId the tag handle (as returned from a call to StorageRegistry.registerTag)
 */
void StorageEntry::addTag(int tagId)
{
    if(isMetadataEntry)
    {
        throw RuntimeException("Tags cannot be set on metadata", RuntimeException::USAGE_ERROR);
    }

    checkThatRangeIsValid(tagId,maxTags);
    
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
 * @param tagId the tag handle (as returned from a call to StorageRegistry.registerTag)
 */
void StorageEntry::removeTag(int tagId)
{
    if(isMetadataEntry)
    {
        throw RuntimeException( "Tags cannot be set on metadata", RuntimeException::USAGE_ERROR);
    }

    checkThatRangeIsValid(tagId,maxTags);

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
 * @param tagId the tag handle (as returned from a call to StorageRegistry.registerTag)
 * @returns true if the entry has the tag, and false otherwise
 */
bool StorageEntry::hasTag(int tagId)
{
    if(isMetadataEntry)
    {
        throw RuntimeException( "Metadata does not have tags", RuntimeException::USAGE_ERROR);
    }

    checkThatRangeIsValid(tagId,maxTags);

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
            tagList.push_back(i);
        }
    } 
    return tagList;
}
