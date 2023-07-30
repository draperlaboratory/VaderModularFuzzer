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

#include "Module.hpp"
#include "StorageEntry.hpp"
#include "StorageEntryListener.hpp"
#include "Iterator.hpp"
#include <memory>

namespace vader
{
/**
 * @brief Base class for Vader Storage Modules
 *
 * Storage modules provide for storage of test cases and their associated data.  Support
 * for global metadata variables is provided as well.
 *
 */
class StorageModule : public Module, public StorageEntryListener {
public:

    /** Destructor */
    virtual ~StorageModule() {};

    //-----------------Used by the Vader Application-----------------------
    virtual void init(ConfigInterface& config) = 0;

    /**
     * @brief Configure storage
     *
     * This method should only be called by the vader application, and must be
     * called before anything is read or written to storage.
     *
     * @param registry the fields and tags that must be maintained by storage
     * @param metadata the field maintained in the metadata (tags are not supported)
     */
    virtual void configure(StorageRegistry* registry, StorageRegistry* metadata) = 0;

    //-----------------Used by the Storage Entry--------------------------
    /**
     * @brief Notify storage that the sort by key value has changed
     * 
     * This method should only be called by the StorageEntry itself, to notify
     * storage when the sort by key is changed.  User's of storage do not need
     * to call this method directly.
     * 
     * @param entry the storage entry that changed
     */
    virtual void notifyPrimaryKeyUpdated(StorageEntry* entry) = 0;

    //-----------------Used by the Vader Controller-----------------------
    /**
     * @brief Clear the list of new entries and tags
     *
     * This method should only be called by the controller module.  After calling this,
     * getNewEntries and getNewEntriesByTag will not return any elements untill createNewEntry
     * or tagEntry is called again.  All new entries must be either saved or discarded prior to calling
     * this method, or memory leaks may occur.
     */
    virtual void clearNewEntriesAndTags() = 0;

    //-----------------Used by Vader modules-----------------

    /**
     * @brief Create a New Entry object
     *
     * New entries are not sorted, and need not neccesarily have yet defined the sort by fields.
     * New entries will be cleared on each call to clearNewEntriesAndTags unless saveEntry() is called,
     * indicating that the entry should be saved in long term storage.
     *
     * @return StorageEntry* a pointer to the newly created entry
     */
    virtual StorageEntry* createNewEntry() = 0; 

    /**
     * @brief Get all the new entries
     *
     * Returns an iterator that will step through all of the new entries.
     *
     * @return std::unique_ptr<Iterator> the iterator
     */
    virtual std::unique_ptr<Iterator> getNewEntries() = 0;

    /**
     * @brief Get all the new entries that have the provided tag
     *
     * Returns an iterator that will step through all of the new entries that have the provided tag.
     *
     * @return std::unique_ptr<Iterator> the iterator
     */
    virtual std::unique_ptr<Iterator> getNewEntriesByTag(int tagId) = 0;

    /**
     * @brief Get the New Entries That Will Be Saved
     *
     * Returns an interator that will step through of the entries that were saved since the last
     * call to clearNewEntriesAndTags();
     *
     * @return std::unique_ptr<Iterator> the iterator
     */
    virtual std::unique_ptr<Iterator> getNewEntriesThatWillBeSaved() = 0;

    /**
     * @brief Save the entry to long term storage
     *
     * Note that long term storage is sorted by the sort by key (configured in StorageRegistry), so the
     * sort by key's value must be written to the entry prior to calling this method.
     *
     * @param e
     */
    virtual void saveEntry(StorageEntry* e) = 0;

    /**
     * @brief Removes a previously saved entry
     *
     * Only use this method to remove entries that have been saved to long term storage.
     *
     * @param e the entry to remove
     */
    virtual void removeEntry(StorageEntry* e) = 0;

    /**
     * @brief Tag a entry as having a particular attribute
     *
     * The tag must have been previously registed with the StorageRegistry.  All
     * new entries that are tagged will be automatically saved as well.
     *
     * @param e the entry to tag
     * @param tagId the tag handle (as returned from a call to StorageRegistry.registerTag)
     */
    virtual void tagEntry(StorageEntry* e, int tagId) = 0;

    /**
     * @brief Remove a tag from an entry
     * 
     * This removes a tag from a previously tagged entry.  Untagging an entry will
     * not change anything about whether it is saved.
     * 
     * @param e the entry to remove the tag from
     * @param tagId the tag handle (as returned from a call to StorageRegistry.registerTag)
     */
    virtual void unTagEntry(StorageEntry* e, int tagId) = 0;

    /**
     * @brief Check if an entry has a particular tag.
     * 
     *
     * @param e the entry to check the tag on.
     * @param tagId the tag handle (as returned from a call to StorageRegistry.registerTag)
     */
    virtual bool entryHasTag(StorageEntry* e, int tagId) = 0;  

    /**
     * @brief Return all the tags for this storage entry
     * This is returned as a list of tag handles
     * 
     * @param e the entry of interest
     * @return std::vector<int> the list of tag handles
     */
    virtual std::vector<int> getEntryTagList(StorageEntry* e) = 0;

    /**
     * @brief Get all the tag handles that storage is tracking
     * This returns the list of all registered tag handles in storage.
     * Modules that want to generically handle all tags should use this
     * method sometime after initialization to retrieve all of the relevant tags.
     * 
     * @return std::vector<int> the list of tag handles
     */
    virtual std::vector<int> getListOfTagHandles() = 0;

    /**
     * @brief Convert a tag handle to the registered tag name
     * Modules may use this method to convert a tag handle to the associated
     * tag name.  This is useful for modules that generically support handling
     * all tags in the system.
     * 
     * @param tagId the tag handle
     * @return std::string the name associated with the tag
     */
    virtual std::string tagHandleToString(int tagId) = 0;

    /**
     * @brief Get all the entries that have been previously tagged with the provided tag.
     *
     * Returns an iterator that can be used to step through all of the tagged entries.
     * Entries are sorted using the sort by fields that were configured in the StorageRegistry.
     *
     * @param tagId the tag handle (as returned from a call to StoragRegistry.registerTag)
     * @return std::unique_ptr<Iterator> the iterator
     */
    virtual std::unique_ptr<Iterator> getEntriesByTag(int tagId) = 0;

    /**
     * @brief Get all the entries in long term storage (regardless of whether or not they have been tagged)
     *
     * Returns an iterator that can be used to step through all of the entries in long term storage.
     * Entries are sorted using the sort by fields that were configured in the StorageRegistry.
     *
     * @return std::unique_ptr<Iterator> the iterator
     */
    virtual std::unique_ptr<Iterator> getEntries() = 0;

    /**
     * @brief Retrieves a storage entry by it's unique ID
     * 
     * This can be used for modules that need to keep track of a complex data structure
     * that cannot be maintained within storage.
     * 
     * @param id the id to retrieve
     * @return StorageEntry* or a nullptr if no such entry is found
     */
    virtual StorageEntry* getEntryByID(unsigned long id) = 0;

    /**
     * @brief Retrieves a storage entry with a particular tag by it's unique ID
     * 
     * This can be used for modules that need to keep track of a complex data structure
     * that cannot be maintained within storage.  This version of the method constrains
     * the lookup to entries that also have the specified tag.  In some implementations of
     * storage this will be faster than the version of getEntryByID that does not take a tag.
     * 
     * @param id the id to retrieve
     * @param tagId the tag handle (as returned from a call to StoragRegistry.registerTag)
     * @return StorageEntry* or a nullptr if no such entry is found
     */
    virtual StorageEntry* getEntryByID(unsigned long id, int tagId) = 0;

    /**
     * @brief Returns the metadata object
     *
     * This special storage entry is for global data that is used to store metadata that is
     * shared between modules, but are not specific to an individual entry.
     *
     * @return StorageEntry& the metadata object
     */
    virtual StorageEntry& getMetadata() = 0;

    /**
     * @brief Convenience method to determine if a module is actually a storage module
     * 
     * @param module 
     * @return true if this module has a module type=STORAGE
     * @return false 
     */
    static bool isAnInstance(Module* module)
    {
        ModuleTypeEnum type = module->getModuleType();
        return (ModuleTypeEnum::STORAGE == type);
    }

    /**
     * @brief Convenience method to cast Module* to StorageModule*
     * 
     * Call isAnInstance first to check the type in order to avoid an exception.
     * 
     * @param module 
     * @return StorageModule* 
     * @throws RuntimeException if the underlying Module* is not a decendant of StorageModule
     */
    static StorageModule* castTo(Module* module)
    {
        StorageModule* storage;
        if(nullptr != module)
        {
            storage = dynamic_cast<StorageModule*>(module);
        
            if(nullptr == storage)
            {
                throw RuntimeException("Failed attempt to cast module to StorageModule",
                                    RuntimeException::USAGE_ERROR);
            }
        }
        else
        {
            throw RuntimeException("Attempt to cast nullptr to StorageModule",
                                   RuntimeException::UNEXPECTED_ERROR);
        }
        return storage;
    }

protected:
    /**
     * @brief Construct a new Storage Module object
     * 
     * @param name the name of the module
     */
    StorageModule(std::string name) : Module(name, ModuleTypeEnum::STORAGE) {};

};
}
