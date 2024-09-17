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
#include "SimpleStorage.hpp"
#include "StorageKeyHelper.hpp"
#include "Logging.hpp"

using namespace vmf;

#include "ModuleFactory.hpp"
REGISTER_MODULE(SimpleStorage);

/**
 * @brief Builder method to support the ModuleFactory
 * Constructs an instance of this class
 * @return Module* 
 */
Module* SimpleStorage::build(std::string name)
{
    return new SimpleStorage(name);
}

/**
 * @brief Construct a new Simple Storage object
 * 
 * @param name the name of the module
 */
SimpleStorage::SimpleStorage(std::string name) : StorageModule(name)
{
    metadataEntry = nullptr;
    numTags = 0;
    sortDescending = false;
    registry = nullptr;
}

SimpleStorage::~SimpleStorage()
{
    //First resolve any lingering memory actions
    clearNewAndLocalEntries();

    //Now delete all entries in long term storage
    for(StorageEntry* entry: entryList)
    {
        delete entry;
    }
    
    //This could be null if SimpleStorage is destroyed before init is called
    if(nullptr != metadataEntry)
    {
        delete metadataEntry;
    }
  
}

void SimpleStorage::init(ConfigInterface& config)
{
    //Nothing needed from the config file
}

void SimpleStorage::configure(StorageRegistry* registry, StorageRegistry* metadata)
{
    this->registry = registry;
    numTags = registry->getNumTags();
    sortDescending = (StorageRegistry::DESCENDING == registry->getSortByOrder());

    //Provide sizing information to the StorageEntries
    StorageEntry::init(*registry);
    StorageEntry::initMetadata(*metadata);

    for(int i=0; i<numTags; i++)
    {
        //For each tag, create a list to store the entries that have that tag
        //Two lists are needed, as a seperate list of tags is maintained for new entries
        std::list<StorageEntry*>* tagListEntry = new std::list<StorageEntry*>;
        std::list<StorageEntry*>* newTagListEntry = new std::list<StorageEntry*>;
        tagList.push_back(*tagListEntry);
        newTagList.push_back(*newTagListEntry);
	    delete tagListEntry; // These were copied into tagLists, can delete now
	    delete newTagListEntry;
    }

    //Construct the metadata object
    metadataEntry = new StorageEntry(true, false, this);
    metadataTempBuffSet = false;
    initialized = true;

    //Save a copy of this information, so it does not have to be created each time
    tagNameMap = registry->getTagNameMap();
    tagHandles = registry->getTagHandles();
    tmpBufferHandles = registry->getKeyHandles(StorageRegistry::BUFFER_TEMP);
    metaKeyHandleMap[StorageRegistry::INT] = metadata->getKeyHandles(StorageRegistry::INT);
    metaKeyHandleMap[StorageRegistry::UINT] = metadata->getKeyHandles(StorageRegistry::UINT);
    metaKeyHandleMap[StorageRegistry::FLOAT] = metadata->getKeyHandles(StorageRegistry::FLOAT);
    metaKeyHandleMap[StorageRegistry::BUFFER] = metadata->getKeyHandles(StorageRegistry::BUFFER);
    metaKeyHandleMap[StorageRegistry::BUFFER_TEMP] = metadata->getKeyHandles(StorageRegistry::BUFFER_TEMP);
    metaKeyNameMap = metadata->getKeyNameMap();
}

/**
* Treat all "new entries" as no longer being new.  The parameters needed by the provided
* comparison function must be computed on each new entry prior to this process.
*/
void SimpleStorage::clearNewAndLocalEntries()
{
    //Clear the temp buffers (do this first, as some of these entries may
    //be about to be deleted, but we don't know which ones)
    for(StorageEntry* buffEntry: tempBufferModList)
    {
        for(int handle: tmpBufferHandles)
        {
            buffEntry->clearBuffer(handle);
        }
    }
    tempBufferModList.clear();
    std::vector<int> tmpMetaBufferHandles = metaKeyHandleMap[StorageRegistry::BUFFER_TEMP];
    if(metadataTempBuffSet)
    {
        for(int handle: tmpMetaBufferHandles)
        {
            metadataEntry->clearBuffer(handle);
        }
        metadataTempBuffSet = false;
    }

    //Clear the list of "new" elements
    for(StorageEntry* newEntry: newList)
    {
        //Delete any new entry that has not been flagged to save
        bool onSaveList = containsEntry(saveList, newEntry);

        if(!onSaveList)
        {
            delete newEntry;
        }
    }
    newList.clear();

    //Clear the local elements
    for(StorageEntry* localEntry: localList)
    {
        delete localEntry;
    }
    localList.clear();

    //Delete all the entries that were flagged for deletion
    for(StorageEntry* e: deleteList)
    {
         //Remove the entry from any tagged lists
        for(size_t i=0; i<tagList.size(); i++)
        {
	        removeEntryIfPresent(tagList[i],e);
            //does not need to be removed from newTagList because this list is cleared fully
            //later in this method
        }

        //Remove the entry itself and free the associated memory
        removeEntryIfPresent(entryList,e);
        delete e;
    }
    deleteList.clear();

    //Clear the list of newly saved elements
    saveList.clear();

    //Clear all the tag lists for "new" elements
    //for(list<StorageEntry*> sublist: newTagList) //This version doesn't work
    for(int i=0; i<numTags; i++)
    {
        newTagList[i].clear();
    }
}

void SimpleStorage::notifyPrimaryKeyUpdated(StorageEntry* entry)
{
    bool found = removeEntryIfPresent(entryList,entry);
    if(found)
    {
        insertEntrySorted(entryList, entry, sortDescending);
    }
}

void SimpleStorage::notifyTempBufferSet(StorageEntry* entry, bool isMetadata)
{
    if(!isMetadata)
    {
        tempBufferModList.push_back(entry);
    }
    else
    {
        metadataTempBuffSet = true;
    }

}

StorageEntry* SimpleStorage::createNewEntry()
{
    if(initialized)
    {
        StorageEntry* entry = new StorageEntry(false, false, this);
        newList.push_back(entry); //a pointer to the new entry, for quick lookup of new elements
        return entry;
    }
    else
    {
        throw RuntimeException("Storage must be initialized before use.", RuntimeException::USAGE_ERROR);
    }
}

StorageEntry* SimpleStorage::createLocalEntry()
{
    if(initialized)
    {
        StorageEntry* entry = new StorageEntry(false, true, this);
        localList.push_back(entry);
        return entry;
    }
    else
    {
        throw RuntimeException("Storage must be initialized before use.", RuntimeException::USAGE_ERROR);
    }
}; 

void SimpleStorage::removeLocalEntry(StorageEntry*& entry)
{
    if(entry->isLocalEntry())
    {
        //We must also remove from the tempBufferModList, as otherwise we will
        //have an attempt to access freed memory when we go to clear temp buffers
        tempBufferModList.remove(entry); 
        localList.remove(entry); //Note: This did not work properly when done with removeEntryIfPresent
        delete entry;
        entry = nullptr;
    }
    else
    {
         throw RuntimeException("removaLocalEntry() can only be called on entries that were allocated with createLocalEntry()", 
                                RuntimeException::USAGE_ERROR);
    }
};

void SimpleStorage::saveEntry(StorageEntry* e)
{
    if(e->getID() == metadataEntry->getID())
    {
        throw RuntimeException( "Metadata cannot be saved",RuntimeException::USAGE_ERROR);
    }

    if(e->isLocalEntry())
    {
        throw RuntimeException("Local entries cannot be saved", RuntimeException::USAGE_ERROR);
    }

    //Save a reference to the entry for a quick look-up of newly saved entries
    //(Check that this entry isn't already on the save list first, if it is already
    //on the save list, then it has already been saved on this pass)
    if(!(containsEntry(saveList,e)))
    {
        saveList.push_back(e);

        insertEntrySorted(entryList,e,sortDescending);

        //If the entry has any tags, we need to update the tagList to reflect those tags
        //(as the tags were initially only set on the newTagList)
        std::vector<int> setTagIds = e->getTagList();

        //For each tag that has been set, add it to the appropriate tagList
        for(int tagId: setTagIds)
        {
            insertEntrySorted(tagList[tagId],e,sortDescending);
        }
    }
}

/**
 * @brief Remove an entry from storage
 * This flags an entry for removal.  The actual deletion will happen during clearNewAndLocalEntries.
 *
 * @param e the storage entry to remove
 */
void SimpleStorage::removeEntry(StorageEntry* e)
{

    if(e->getID() == metadataEntry->getID())
    {
        throw RuntimeException( "Metadata cannot be removed",RuntimeException::USAGE_ERROR);
    }

    if(e->isLocalEntry())
    {
        throw RuntimeException("Local entries cannot be removed", RuntimeException::USAGE_ERROR);
    }

    deleteList.push_back(e);
}

/**
 * @brief Helper method to remove an entry if it is present
 * Returns false if the entry was not found
 * @param list the list to remove from
 * @param entry the element to removew
 */
bool SimpleStorage::removeEntryIfPresent(std::list<StorageEntry*>& list, StorageEntry* entry)
{
    bool onList = false;
    std::list<StorageEntry*>::iterator it = list.begin();
    while (it != list.end()) {
        if((*it)->getID() == entry->getID())
        {
            it = list.erase(it); //this increments the iterator
            onList = true;
            break;
        }
        else
        {
            it++;
        }
    }

    return onList;
}

/**
 * @brief Checks whether the provided tag is valid.  Returns true if it is and throws an exception otherwise.
 *
 * @param tagId
 * @param numTags
 * @return true if the tag is valid
 * @throws RuntimeException if the tag is invalid
 */
bool SimpleStorage::checkThatTagIsValid(int tagId, int numTags)
{
    int typeMask = StorageKeyHelper::getType(tagId);
    if(typeMask != StorageKeyHelper::TAG_TYPE_MASK)
    {
        throw RuntimeException("Attempt to access storage with a key of the wrong type (expected a tag type)", RuntimeException::USAGE_ERROR);
    }

    int index = StorageKeyHelper::getIndex(tagId);
    if(!((index >= 0) && (index < numTags)))
    {
        throw RuntimeException( "Invalid tag in call to SimpleStorage",RuntimeException::INDEX_OUT_OF_RANGE);
    }
    return true;
}

/**
 * @brief Helper method to check whether an entry is on a particular list
 * 
 * @param list the list
 * @param entry the entry
 * @return true if the list contains the entry
 * @return false otherwise
 */
bool SimpleStorage::containsEntry(std::list<StorageEntry*>& list, StorageEntry* entry)
{
    bool onList = false;
    for(StorageEntry* nextEntry: list)
    {
        if(nextEntry->getID() == entry->getID())
        {
            onList = true;
            break;
        }
    }

    return onList;
}

/**
 * @brief Helper method to insert an entry into the provided sorted list
 * 
 * @param list the list to insert into
 * @param entry the entry
 * @param sortDescending whether or not to sort descending
 */
void SimpleStorage::insertEntrySorted(std::list<StorageEntry*>& list, StorageEntry* entry, bool sortDescending)
{
    bool found = false;
    std::list<StorageEntry*>::iterator it;

    for(it = list.begin(); it != list.end(); ++it)
    {
        if(sortDescending)
        {
            if(!(entry->sortByValueIsLessThan(*(*it)))) //Find the first thing that the new element is not less than
            {
                //Insert right before this element
                found = true;
                break;
            }
        }
        else
        {
            if(entry->sortByValueIsLessThan(*(*it))) //Find the first thing that the new element is less than
            {
                //Insert right before this element
                found = true;
                break;
            }
        }
    }

    if(found)
    {
        list.insert(it, entry);
    }
    else
    {
        //Add to the end of the list
        list.push_back(entry);
    }
}

void SimpleStorage::notifyTagSet(StorageEntry* e, int tagId)
{
    if(e->getID() == metadataEntry->getID())
    {
        throw RuntimeException( "StorageEntry should not allow tagging of Metadata",RuntimeException::USAGE_ERROR);
    }

    if(e->isLocalEntry())
    {
        throw RuntimeException("StorageEntry should not notify Storage if local entries are tagged", 
                                RuntimeException::USAGE_ERROR);
    }

    checkThatTagIsValid(tagId, numTags);

    //Check to see if this is a new entry
    bool isNew = containsEntry(newList, e);
    bool isOnSaveList = containsEntry(saveList, e);
    //New entries go on the newTagList
    if(isNew)
    {
        //Write this entry to the newTagList for this tagId (if it is not already there)
        if(!containsEntry(newTagList[tagId],e))
        {
            newTagList[tagId].push_back(e);
        }
    }

    //Saved entries go on the tagList (this includes entries that are new but that have just been saved)
    if(!isNew || isOnSaveList)
    {
        //Write this entry to the TagList for this tagId (if it is not already there)
        if(!containsEntry(tagList[tagId], e))
        {
            insertEntrySorted(tagList[tagId],e,sortDescending);
        }
    }
}

void SimpleStorage::notifyTagRemoved(StorageEntry* e, int tagId)
{
    if(e->getID() == metadataEntry->getID())
    {
        throw RuntimeException( "StorageEntry should not allow tagging of Metadata",RuntimeException::USAGE_ERROR);
    }

    if(e->isLocalEntry())
    {
        throw RuntimeException("StorageEntry should not notify Storage about local entry tags", 
                                RuntimeException::USAGE_ERROR);
    }

    checkThatTagIsValid(tagId, numTags);

    removeEntryIfPresent(tagList[tagId],e);
    removeEntryIfPresent(newTagList[tagId],e);
}

std::vector<int> SimpleStorage::getListOfTagHandles()
{
    return tagHandles;
}

std::string SimpleStorage::tagHandleToString(int tagId)
{
    checkThatTagIsValid(tagId, numTags);
    return tagNameMap[tagId];
}

std::vector<int> SimpleStorage::getListOfMetadataKeyHandles(StorageRegistry::storageTypes type)
{
    return metaKeyHandleMap[type];
}

std::string SimpleStorage::metadataKeyHandleToString(int handle)
{
    //First make sure the handle is valid
    int typeMask = StorageKeyHelper::getType(handle);
    int index = StorageKeyHelper::getIndex(handle);
    StorageRegistry::storageTypes typeEnum = StorageKeyHelper::typeToEnum(typeMask);
    int numKeys = metaKeyHandleMap[typeEnum].size();
    if(!((index >= 0) && (index < numKeys)))
    {
        throw RuntimeException( "Invalid key handle in call to SimpleStorage",RuntimeException::INDEX_OUT_OF_RANGE);
    }

    //Now return the value
    return metaKeyNameMap[handle];
}

std::unique_ptr<Iterator> SimpleStorage::getSavedEntriesByTag(int tagId)
{
    checkThatTagIsValid(tagId, numTags);

    SimpleIterator* theIterator = new SimpleIterator(tagList[tagId]);
    std::unique_ptr<Iterator> returnPointer(theIterator);
    return returnPointer;
}

std::unique_ptr<Iterator> SimpleStorage::getNewEntriesByTag(int tagId)
{
    checkThatTagIsValid(tagId, numTags);

    SimpleIterator* theIterator = new SimpleIterator(newTagList[tagId]);
    std::unique_ptr<Iterator> returnPointer(theIterator);
    return returnPointer;
}

std::unique_ptr<Iterator> SimpleStorage::getNewEntriesThatWillBeSaved()
{
    SimpleIterator* theIterator = new SimpleIterator(saveList);
    std::unique_ptr<Iterator> returnPointer(theIterator);
    return returnPointer;
}

std::unique_ptr<Iterator> SimpleStorage::getSavedEntries()
{
    SimpleIterator* theIterator = new SimpleIterator(entryList);
    std::unique_ptr<Iterator> returnPointer(theIterator);
    return returnPointer;
}

StorageEntry* SimpleStorage::getSavedEntryByID(unsigned long id)
{
    for(StorageEntry* nextEntry: entryList)
    {
        if(id == nextEntry->getID())
        {
            return nextEntry;
            break;
        }
    }

    //ID was not found
    return nullptr;
}

 StorageEntry* SimpleStorage::getSavedEntryByID(unsigned long id, int tagId)
 {
    checkThatTagIsValid(tagId, numTags);

    for(StorageEntry* nextEntry: tagList[tagId])
    {
        if(id == nextEntry->getID())
        {
            return nextEntry;
            break;
        }
    }

    //ID was not found
    return nullptr;
 }

std::unique_ptr<Iterator> SimpleStorage::getNewEntries()
{
    SimpleIterator* theIterator = new SimpleIterator(newList);
    std::unique_ptr<Iterator> returnPointer(theIterator);
    return returnPointer;
}

StorageEntry& SimpleStorage::getMetadata()
{
    if(initialized)
    {
        return *metadataEntry;
    }
    else
    {
        throw RuntimeException("Storage must be initialized before use.", RuntimeException::USAGE_ERROR);
    }
}
