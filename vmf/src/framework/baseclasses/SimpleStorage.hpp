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

#include "StorageModule.hpp"
#include "StorageRegistry.hpp"
#include "StorageEntry.hpp"
#include "Iterator.hpp"
#include "RuntimeException.hpp"

#include "SimpleIterator.hpp"


#include <vector>
#include <list>
#include <unordered_map>

namespace vmf{
/**
 * @brief Simple implementation of a storage module.  
 * This implementation is not thread safe.  All storageEntries and associated memory
 * are stored in RAM with non-thread-safe accessors.
 */
class SimpleStorage: public StorageModule
{
public:
    static Module* build(std::string name);
    SimpleStorage(std::string name);
    virtual ~SimpleStorage();

    //Used by VMF application, Controller, StorageEntry
    virtual void init(ConfigInterface& config);
    virtual void configure(StorageRegistry* registry, StorageRegistry* metadata);
    virtual void clearNewAndLocalEntries();
    virtual void notifyPrimaryKeyUpdated(StorageEntry* entry);
    virtual void notifyTagSet(StorageEntry* entry, int tagId);
    virtual void notifyTagRemoved(StorageEntry* entry, int tagId);
    virtual void notifyTempBufferSet(StorageEntry* entry, bool isMetadata);

    //--------Used by modules-----------------
    //These methods are for local entries only
    virtual StorageEntry* createLocalEntry();
    virtual void removeLocalEntry(StorageEntry*& entry);

    //These methods are for "new" entries, these entries are cleared on each pass of the controller
    //These entries are not sorted, and need not necesarily have yet defined all the fields that are
    //required for the comparison function
    virtual StorageEntry* createNewEntry(); //All new entries must either be saved or discarded to avoid memory leaks
    virtual std::unique_ptr<Iterator> getNewEntries();
    virtual std::unique_ptr<Iterator> getNewEntriesByTag(int tagId);
    virtual std::unique_ptr<Iterator> getNewEntriesThatWillBeSaved();

    //These methods are for entries that we want to maintain longer term.  "new" entries must be added
    //using the saveEntry method in order to be maintained in long term storage.  This set of entries
    //is sorted using the provided comparison function
    virtual void saveEntry(StorageEntry* e); //Save a new entry for long term storage
    virtual void removeEntry(StorageEntry* e); //Remove a previously savedEntry
    virtual std::unique_ptr<Iterator> getSavedEntriesByTag(int tagId); //return a sorted list of saved entries by tag
    virtual std::unique_ptr<Iterator> getSavedEntries(); //return a sorted list of saved entries

    //These methods provide a way to retrieve an saved entry by id ()
    virtual StorageEntry* getSavedEntryByID(unsigned long id);
    virtual StorageEntry* getSavedEntryByID(unsigned long id, int tagId);

    //These methods are helper methods for working with tags in a generic way
    virtual std::vector<int> getListOfTagHandles(); //Get a list of all the tags ids used by storage
    virtual std::string tagHandleToString(int tagId); //Convert a tag id to a human readable string

    //These methods are helper methods for working with keys in a generic way
    virtual std::vector<int> getListOfMetadataKeyHandles(StorageRegistry::storageTypes type);
    virtual std::string metadataKeyHandleToString(int handle); //Convert a key handle to a human readable string

    //This method returns the one and only metadata storage entry
    virtual StorageEntry& getMetadata();

private:
    static bool removeEntryIfPresent(std::list<StorageEntry*>& list, StorageEntry* entry);
    static bool checkThatTagIsValid(int tagId, int numTags);
    static bool containsEntry(std::list<StorageEntry*>& list, StorageEntry* entry);
    static void insertEntrySorted(std::list<StorageEntry*>& list, StorageEntry* entry, bool sortDescending);

    //Note: This is not a thread safe implementation
    //Update if thread safety is needed

    ///Flag to keep track of whether or not storage has been intialized (for error handling)
    bool initialized = false;

    ///This is a sorted list of entries that have been saved to long term storage
    std::list<StorageEntry*> entryList;

    /**
     * @brief This is an unsorted list of "new" elements only
     *
     * Note that elements are maintained temporarily on the new list.  Each time clearNewAndLocalEntries is
     * called, this list is cleared. 
     */
    std::list<StorageEntry*> newList; 

    /**
     * @brief This is an unsorted list of "local" temporary elements only
     * 
     * Local elements are accessible only to the module that created them.  They will never be returned
     * from any of the other methods in storage.  Note that elements are maintained temporarily on the 
     * local list.  Each time clearNewAndLocalEntries is called, this list is cleared.
     */
    std::list<StorageEntry*> localList;

    /**
     * @brief Temporary storage for entries from the new list that were just saved
     *
     * Note that elements are actually saved as soon as saveEntry is called
     */
    std::list<StorageEntry*> saveList;

    /**
     * @brief Temporary storage for entries that were just deleted
     * 
     * Note that elements are not deleted until clearNewAndLocalEntries is called.
     */
    std::list<StorageEntry*> deleteList;

    /**
     * @brief Temporary storage for entries with modified temporary buffers
     * 
     * This list is used to clear temporary buffers when clearNewAndLocalEntries is called.
     */
    std::list<StorageEntry*> tempBufferModList;

    /**
     * @brief The list of temp buffer handles
     * 
     * This is retrieved from the storage registry and used to know which buffers to clear
     * on the entries on the tempBufferModList;
     */
    std::vector<int> tmpBufferHandles;


    /**
     * @brief Flag to indicate whether or not metadata temp buffers have been set
     * 
     */
    bool metadataTempBuffSet;

    //NOTE: Be careful when accessing these datastructures (tagList and newTagList)
    //Using a for-each loop can cause accidental copies (using tagList[i] should prevent this)
    //See: https://stackoverflow.com/questions/51387535/c-range-based-for-loop-is-the-container-copied

    /**
     * @brief The list of entries that have been tagged
     *
     * This is a vector that is indexed by tag handle.  Each list<StorageEntry*> is the list of entries
     * that are associated with a particular tag.  This provides quick access to the list of tagged elements
     * without searching through storage.
     * 
     * Each sublist is sorted by primary key.
     */
    std::vector<std::list<StorageEntry*>> tagList;

    /**
     * @brief The list of new entires that have been tagged
     *
     * This is distinct from tagList in that it only maintains "newly" tagged entries.  This list will be cleared on
     * each call to clearNewAndLocalEntries.  This is a vector that is indexed by tag handle.  Each list<StorageEntry*>
     * is the list of new entries that are associated with a particular tag.  This provides quick access to the list of
     * newly tagged elements without searching through storage (for example, the list of new elements that CRASHED).
     */
    std::vector<std::list<StorageEntry*>> newTagList;

    int numTags; ///Stores the number of tags (retrieved from the StorageRegistry during init)
    bool sortDescending; ///true if the sort order is descending (configured from the StorageRegistry during init)

    ///A pointer to the storage registy (this is maintained as each newly constructed StorageEntry needs this data)
    StorageRegistry* registry;

    ///The metadata object
    StorageEntry* metadataEntry;

    ///Map of human readable version of tag names (indexed by tag handle)
    std::unordered_map<int,std::string> tagNameMap;

    ///Map of human readable key names (indexed by key handle)
    std::unordered_map<int,std::string> metaKeyNameMap;

    ///List of tag handles
    std::vector<int> tagHandles;

    //Map of data types to key handles
    std::unordered_map<StorageRegistry::storageTypes,std::vector<int>> metaKeyHandleMap;

};
}
