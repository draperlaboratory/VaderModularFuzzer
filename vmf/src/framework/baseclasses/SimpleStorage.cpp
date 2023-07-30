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
#include "SimpleStorage.hpp"

using namespace vader;

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
    clearNewEntriesAndTags();

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
    }

    //Construct the metadata object
    metadataEntry = new StorageEntry(true, this);
    initialized = true;

    //Save a copy of this information, so it does not have to be created each time
    tagNames = registry->getTagNames();
    tagHandles = registry->getTagHandles();
}

/**
* Treat all "new entries" as no longer being new.  The parameters needed by the provided
* comparison function must be computed on each new entry prior to this process.
*/
void SimpleStorage::clearNewEntriesAndTags()
{
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

StorageEntry* SimpleStorage::createNewEntry()
{
    if(initialized)
    {
        StorageEntry* entry = new StorageEntry(false, this);
        newList.push_back(entry); //a pointer to the new entry, for quick lookup of new elements
        return entry;
    }
    else
    {
        throw RuntimeException("Storage must be initialized before use.", RuntimeException::USAGE_ERROR);
    }
}

void SimpleStorage::saveEntry(StorageEntry* e)
{
    if(e->getID() == metadataEntry->getID())
    {
        throw RuntimeException( "Metadata cannot be saved",RuntimeException::USAGE_ERROR);
    }

    //Save a reference to the entry for a quick look-up of newly saved entries
    //(Check that this entry isn't already on the save list first, if it is already
    //on the save list, then it has already been saved on this pass)
    if(!(containsEntry(saveList,e)))
    {
        saveList.push_back(e);

        insertEntrySorted(entryList,e,sortDescending);
    }
}

/**
 * @brief Remove an entry from storage
 * This flags an entry for removal.  The actual deletion will happen during clearNewEntriesAndTags.
 *
 * @param e the storage entry to remove
 */
void SimpleStorage::removeEntry(StorageEntry* e)
{

    if(e->getID() == metadataEntry->getID())
    {
        throw RuntimeException( "Metadata cannot be removed",RuntimeException::USAGE_ERROR);
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
    if(!((tagId >= 0) && (tagId < numTags)))
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

void SimpleStorage::tagEntry(StorageEntry* e, int tagId)
{

    if(e->getID() == metadataEntry->getID())
    {
        throw RuntimeException( "Metadata cannot be tagged",RuntimeException::USAGE_ERROR);
    }

    checkThatTagIsValid(tagId, numTags);

    //Note: Technically a non-new entry could be tagged with this method, though
    //it would still appear on the newTagList.  This is likely a desireable behavior, however.
    if(!containsEntry(tagList[tagId], e))
    {
        insertEntrySorted(tagList[tagId],e,sortDescending);
    }

    if(!containsEntry(newTagList[tagId],e))
    {
        newTagList[tagId].push_back(e);
    }

    //If this is a new entry, then also add the entry to the save list, 
    //if it is not already there.
    //Note: This be fastest if the entry is saved prior to tagging
    bool alreadyOnSavedList = containsEntry(saveList,e);
    if(!alreadyOnSavedList)
    {
        //Confirm that this is a new entry
        bool isNew = containsEntry(newList, e);
        if(isNew)
        {
            saveEntry(e);
        }
        //else, this is an old entry, and hence has been already saved
    }

    //Check to see if the entry already has a tagMap entry, and if not,
    //create one.  Then update the flag for this tag in the tagMap.
    long uid = e->getID();
    auto search = tagMap.find(uid);
    if (search != tagMap.end())
    {
        //This entry already has a tag map, so set the flag for this tag
        (search->second)[tagId] = true;
    }
    else
    {
        //Create a tagMap entry to track the tags for this storage entry
        auto& vec = tagMap[uid];
        vec.resize(numTags);
        for(int i=0; i<numTags; i++)
        {
            vec[i] = false;
        }
        vec[tagId] = true; //set the flag for the current tag
        
    }

}

void SimpleStorage::unTagEntry(StorageEntry* e, int tagId)
{
    if(e->getID() == metadataEntry->getID())
    {
        throw RuntimeException( "Metadata cannot be tagged",RuntimeException::USAGE_ERROR);
    }

    checkThatTagIsValid(tagId, numTags);

    removeEntryIfPresent(tagList[tagId],e);
    removeEntryIfPresent(newTagList[tagId],e);

    //Update the tagMap flag for this tag as well
    long uid = e->getID();
    auto search = tagMap.find(uid);
    if (search != tagMap.end())
    {   
        (search->second)[tagId] = false;
    }
    //If there is no tagMap entry, then it wasn't tagged in the first place
    //and there is nothing to do here

}

bool SimpleStorage::entryHasTag(StorageEntry* e, int tagId)
{
    bool hasTag = false;

    checkThatTagIsValid(tagId, numTags);
    long uid = e->getID();
    auto search = tagMap.find(uid); 
    if (search != tagMap.end())
    {
        hasTag = search->second[tagId];
    }
    //If there is no tagMap entry, then it wasn't tagged in the first place

    return hasTag;
}

std::vector<int> SimpleStorage::getEntryTagList(StorageEntry* e)
{   std::vector<int> tags;
    long uid = e->getID();
    auto search = tagMap.find(uid);
    if (search != tagMap.end())
    {
        for(int i = 0; i<numTags; i++)
        {
            if(search->second[i])
            {
                tags.push_back(i);
            }
        } 
    }
    return tags;
}
std::vector<int> SimpleStorage::getListOfTagHandles()
{
    return tagHandles;
}

std::string SimpleStorage::tagHandleToString(int tagId)
{
    checkThatTagIsValid(tagId, numTags);
    return tagNames[tagId];
}

std::unique_ptr<Iterator> SimpleStorage::getEntriesByTag(int tagId)
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

std::unique_ptr<Iterator> SimpleStorage::getEntries()
{
    SimpleIterator* theIterator = new SimpleIterator(entryList);
    std::unique_ptr<Iterator> returnPointer(theIterator);
    return returnPointer;
}

StorageEntry* SimpleStorage::getEntryByID(unsigned long id)
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

 StorageEntry* SimpleStorage::getEntryByID(unsigned long id, int tagId)
 {
    checkThatTagIsValid(tagId, numTags);

    for(StorageEntry* nextEntry: newTagList[tagId])
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
