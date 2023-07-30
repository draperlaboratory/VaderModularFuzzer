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

#include "StorageModule.hpp"
#include "StorageRegistry.hpp"
#include "StorageEntry.hpp"
#include "Iterator.hpp"
#include "RuntimeException.hpp"

#include "SimpleIterator.hpp"


#include <vector>
#include <list>
#include <unordered_map>

namespace vader{
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

    //Used by Vader application, Controller, StorageEntry
    virtual void init(ConfigInterface& config);
    virtual void configure(StorageRegistry* registry, StorageRegistry* metadata);
    virtual void clearNewEntriesAndTags();
    virtual void notifyPrimaryKeyUpdated(StorageEntry* entry);

    //--------Used by modules-----------------
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
    virtual void tagEntry(StorageEntry* e, int tagId); //Tag an entry
    virtual void unTagEntry(StorageEntry* e, int tagId); //Remove a tag from an entry
    virtual bool entryHasTag(StorageEntry* e, int tagId); //Check if entry has tag
    virtual std::vector<int> getEntryTagList(StorageEntry* e); //Get all the tags for this entry
    virtual std::vector<int> getListOfTagHandles(); //Get a list of all the tags ids used by storage
    virtual std::string tagHandleToString(int tagId); //Convert a tag id to a human readable string

    virtual std::unique_ptr<Iterator> getEntriesByTag(int tagId); //return a sorted list of entries by tag
    virtual std::unique_ptr<Iterator> getEntries(); //return a sorted list of saved entries
    virtual StorageEntry* getEntryByID(unsigned long id);
    virtual StorageEntry* getEntryByID(unsigned long id, int tagId);

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
     * Note that elements are maintained temporarily on the new list.  Each time clearNewEntriesAndTags is
     * called, this list is cleared. 
     */
    std::list<StorageEntry*> newList; ///This is an unsorted list of "new" elements only

    /**
     * @brief Temporary storage for entries from the new list that were just saved
     *
     * Note that elements are actually saved as soon as saveEntry is called
     */
    std::list<StorageEntry*> saveList;

    /**
     * @brief Temporary storage for entries that were just deleted
     * 
     * Note that elements are not deleted until clearNewEntriesAndTags is called.
     */
    std::list<StorageEntry*> deleteList;

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
     * each call to clearNewEntriesAndTags.  This is a vector that is indexed by tag handle.  Each list<StorageEntry*>
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

    ///Hashmap of storage entry ids to the list of tags associated with the entry
    std::unordered_map<long,std::vector<bool>> tagMap;

    ///Human readable version of tag names (indexed by tag handle)
    std::vector<std::string> tagNames;

    ///List of tag handles
    std::vector<int> tagHandles;

};
}
