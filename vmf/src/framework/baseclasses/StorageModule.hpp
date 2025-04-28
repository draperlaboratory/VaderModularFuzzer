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
#pragma once

#include "Module.hpp"
#include "StorageEntry.hpp"
#include "StorageEntryListener.hpp"
#include "Iterator.hpp"
#include <memory>

namespace vmf
{
/**
 * @brief Base class for VMF Storage Modules
 *
 * Storage modules provide for storage of test cases and their associated data.  Support
 * for global metadata variables is provided as well.
 * 
 * Implementors of this base class must also implement all methods in StorageEntryLister.
 * Note that the StorageEntryListener methods, init(), and configure(), are not intended to be used 
 * by other modules.  clearNewAndLocalEntries() should only be called by Controller modules.
 *
 */
class StorageModule : public Module, public StorageEntryListener {
public:

    /** Destructor */
    virtual ~StorageModule() {};

    //-----------------Used by the VMF Application-----------------------
    virtual void init(ConfigInterface& config) = 0;

    /**
     * @brief Configure storage
     *
     * This method should only be called by the VMF application, and must be
     * called before anything is read or written to storage.
     *
     * @param registry the fields and tags that must be maintained by storage
     * @param metadata the field maintained in the metadata (tags are not supported)
     */
    virtual void configure(StorageRegistry* registry, StorageRegistry* metadata) = 0;

    //-----------------Used by the VMF Controller-----------------------
    /**
     * @brief Clear the list of new entries
     *
     * This method should only be called by the controller module.  After calling this,
     * getNewEntries and getNewEntriesByTag will not return any elements until createNewEntry
     * is called again.
     */
    virtual void clearNewAndLocalEntries() = 0;

    //-----------------Used by VMF modules-----------------

    /**
     * @brief Create a New Entry object
     *
     * New entries are not sorted, and need not neccesarily have yet defined the sort by fields.
     * New entries will be cleared on each call to clearNewAndLocalEntries unless saveEntry() is called,
     * indicating that the entry should be saved in long term storage.
     *
     * @return StorageEntry* a pointer to the newly created entry
     */
    virtual StorageEntry* createNewEntry() = 0; 

    /**
     * @brief Create a local Storage Entry object
     *
     * Local entries are to be used only as temporary, local variables.  They are only
     * accessible to the module that created them, and to any submodules that that module
     * passes them to.  Local entries will not persist on the next call to the fuzzing loop
     * (they are cleared on each call to clearNewAndLocalEntries).  Local entries cannot be saved,
     * and will not be returned by any of the other methods in storage.
     *
     * @return StorageEntry* a pointer to the newly created local entry
     */
    virtual StorageEntry* createLocalEntry() = 0; 

    /**
     * @brief Manually remove a local Storage Entry object (the value of the provided pointer will be null after this call)
     * 
     * This method does not have to called, as local entries are automatically freed on every call
     * to clearNewAndLocalEntries.  However, if a module wants to create a large number of local StorageEntries
     * it may be useful to be able to free them to avoid using massive amounts of memory within storage.
     * 
     * @param entry the entry to delete
     * @throws RuntimeException if this method is called on a non-local entry (one that was created with createLocalEntry)
     */
    virtual void removeLocalEntry(StorageEntry*& entry) = 0;

    /**
     * @brief Get all the new entries
     *
     * Returns an iterator that will step through all of the new entries.  The entries will
     * be ordered in the order in which they were created (with the entry that was created
     * first returned first from the iterator).
     *
     * @return std::unique_ptr<Iterator> the iterator
     */
    virtual std::unique_ptr<Iterator> getNewEntries() = 0;

    /**
     * @brief Get all the new entries that have the provided tag
     *
     * Returns an iterator that will step through all of the new entries that have the provided tag.
     * The entries will be ordered in the order in which they were tagged (with the entry that was tagged
     * first returned first from the iterator).
     *
     * @return std::unique_ptr<Iterator> the iterator
     */
    virtual std::unique_ptr<Iterator> getNewEntriesByTag(int tagId) = 0;

    /**
     * @brief Get the New Entries That Will Be Saved
     *
     * Returns an interator that will step through of the entries that were saved since the last
     * call to clearNewAndLocalEntries();
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
     * @brief Get all the metadata key handles that storage is tracking
     * This returns the list of all registered metadata handles in storage.
     * Modules that want to generically handle all metadata keys should use this
     * method sometime after initialization to retrieve all of the relevant keys.
     * 
     * @return std::vector<int> the list of key handles
     */
    virtual std::vector<int> getListOfMetadataKeyHandles(StorageRegistry::storageTypes type) = 0;
    
    /**
     * @brief Convert a metadata key handle to the registered key name
     * Modules may use this method to convert a metadata key handle to the associated
     * key name.  This is useful for modules that generically support handling
     * all metadata in the system.
     * 
     * @param handle the key handle
     * @return std::string the name associated with the key
     */
    virtual std::string metadataKeyHandleToString(int handle) = 0;


    /**
     * @brief Get all the saved entries that have been previously tagged with the provided tag.
     *
     * Returns an iterator that can be used to step through all of the tagged entries.
     * Entries are sorted using the sort by fields that were configured in the StorageRegistry.
     *
     * @param tagId the tag handle (as returned from a call to StoragRegistry.registerTag)
     * @return std::unique_ptr<Iterator> the iterator
     */
    virtual std::unique_ptr<Iterator> getSavedEntriesByTag(int tagId) = 0;

    /**
     * @brief Get all the entries in long term storage (regardless of whether or not they have been tagged)
     *
     * Returns an iterator that can be used to step through all of the entries in long term storage.
     * Entries are sorted using the sort by fields that were configured in the StorageRegistry.
     *
     * @return std::unique_ptr<Iterator> the iterator
     */
    virtual std::unique_ptr<Iterator> getSavedEntries() = 0;

    /**
     * @brief Retrieves a saved storage entry by it's unique ID
     * 
     * This can be used for modules that need to keep track of a complex data structure
     * that cannot be maintained within storage.
     * 
     * @param id the id to retrieve
     * @return StorageEntry* or a nullptr if no such entry is found
     */
    virtual StorageEntry* getSavedEntryByID(unsigned long id) = 0;

    /**
     * @brief Retrieves a saved storage entry with a particular tag by it's unique ID
     * 
     * This can be used for modules that need to keep track of a complex data structure
     * that cannot be maintained within storage.  This version of the method constrains
     * the lookup to entries that also have the specified tag.  In some implementations of
     * storage this will be faster than the version of getSavedEntryByID that does not take a tag.
     * 
     * @param id the id to retrieve
     * @param tagId the tag handle (as returned from a call to StoragRegistry.registerTag)
     * @return StorageEntry* or a nullptr if no such entry is found
     */
    virtual StorageEntry* getSavedEntryByID(unsigned long id, int tagId) = 0;

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
