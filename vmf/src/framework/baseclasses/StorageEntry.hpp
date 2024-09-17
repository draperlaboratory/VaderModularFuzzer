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
#pragma once

#include "StorageRegistry.hpp"
#include "StorageEntryListener.hpp"
#include "RuntimeException.hpp"
#include <vector>

namespace vmf
{
/**
 * @brief The class that stores information about each test case
 *
 * The actual fields that are stored are configurable via the StorageRegistry object.
 *
 */
class StorageEntry
{
public:
    StorageEntry(bool isMetadata, bool isLocal, StorageEntryListener* listener);
    /**
     * @brief Not defined.  StorageEntry should never be copied.
     * All allocations/access for this object should be via the Storage Module.
     * 
     * Be careful when accessing metadata to access it as a reference:
     *   StorageEntry& metadata = storage->getMetadata();
     * Attempts to write the following code will result in a compiler
     * error because the copy constructor would be used instead:
     *   StorageEntry metdata = storage->getMetadata();
     */
    StorageEntry (const StorageEntry&) = delete;
    ~StorageEntry();

    static void init(StorageRegistry& registry);
    static void initMetadata(StorageRegistry& metadata);

    unsigned long getID() const;
    bool isLocalEntry() const;

    bool operator == ( const StorageEntry& e );
    bool sortByValueIsLessThan( const StorageEntry& e );

    void setValue(int key, int value);
    void setValue(int key, unsigned int value);
    void setValue(int key, float value);
    int incrementIntValue(int key);
    unsigned int incrementUIntValue(int key);

    int getIntValue(int key) const;
    unsigned int getUIntValue(int key) const;
    float getFloatValue(int key) const;

    char* allocateBuffer(int key, int size);
    char* allocateAndCopyBuffer(int key, int size, char* srcBuffer);
    char* allocateAndCopyBuffer(int key, StorageEntry* srcEntry);
    void clearBuffer(int key);
    bool hasBuffer(int key) const;
    int getBufferSize(int key) const;
    char* getBufferPointer(int key) const;

    void addTag(int tagId);
    void removeTag(int tagId);
    bool hasTag(int tagId);
    std::vector<int> getTagList();

private:
    static int getHandleIndex(int handle, int expectedType, bool isMetadata, int entryMax, int metaMax);
    static int getBufferHandleIndex(int handle, int isMetadata, bool& isTmpBuffer);

    //Note: This is not a multi-threaded implementation
    static unsigned long uidCounter;
    static int pKey;
    static StorageRegistry::storageTypes pKeyType;
    static int maxInts;
    static int maxUInts;
    static int maxFloats;
    static int maxBuffers;
    static int maxTempBuffers;
    static int maxTags;
    //default values
    static std::vector<int> intDefaults;
    static std::vector<unsigned int> uintDefaults;
    static std::vector<float> floatDefaults;
    static std::vector<int> intMetadataDefaults;
    static std::vector<unsigned int> uintMetadataDefaults;
    static std::vector<float> floatMetadataDefaults;
    //metadata specific parameters
    static int maxIntsMetadata;
    static int maxUIntsMetadata;
    static int maxFloatsMetadata;
    static int maxBuffersMetadata;
    static int maxTempBuffersMetadata;

    unsigned long uid;
    bool isMetadataEntry;
    bool isLocal;
    std::vector<int> intValues;
    std::vector<unsigned int> uintValues;
    std::vector<float> floatValues;
    std::vector<char*> bufferValues;
    std::vector<int> bufferSizes;///Size will equal UNALLOCATED_BUFFER if the buffer is not yet allocated
    std::vector<char*> tmpBufferValues;
    std::vector<int> tmpBufferSizes;
    const int UNALLOCATED_BUFFER = -1;
    std::vector<bool> tagValues;
    
    StorageEntryListener* listener;
};
}