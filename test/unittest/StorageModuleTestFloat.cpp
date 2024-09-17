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
#include "gtest/gtest.h"
#include "SimpleStorage.hpp"
#include <string>
#include <cmath>

using namespace vmf;

namespace my {
namespace project {
namespace {

#define GTEST_COUT std::cerr << "[          ] [ INFO ]"

//This version of the test uses a float as a primary key, with a DESCENDING sort order
class StorageModuleTestFloat: public ::testing::Test
{
protected:
    StorageModuleTestFloat()
    {}

    ~StorageModuleTestFloat() override
    {}

    void SetUp() override {
        storage = new SimpleStorage("storage");

        registry = new StorageRegistry("TEST_FLOAT", StorageRegistry::FLOAT, StorageRegistry::DESCENDING);

        // Setup: add a key to the registry. (this is the sort by key)
        int_key = registry->registerKey(
            "TEST_INT",
            StorageRegistry::INT,
            StorageRegistry::READ_WRITE
        );

        // Setup: add a key to the registry.
        float_key = registry->registerKey(
            "TEST_FLOAT",
            StorageRegistry::FLOAT,
            StorageRegistry::READ_WRITE
        );

        // Setup: add a key to the registry.
        buf_key = registry->registerKey(
            "TEST_BUFFER",
            StorageRegistry::BUFFER,
            StorageRegistry::READ_WRITE
        );

        test_tag = registry->registerTag("TEST_TAG", StorageRegistry::READ_WRITE);
        test_tag2 = registry->registerTag("TEST_TAG2", StorageRegistry::READ_WRITE);

        metadata = new StorageRegistry();
        meta_int_key = metadata->registerKey(
            "META_INT",
            StorageRegistry::INT,
            StorageRegistry::READ_WRITE
        );
        meta_float_key = metadata->registerKey(
            "META_FLOAT",
            StorageRegistry::FLOAT,
            StorageRegistry::READ_WRITE
        );
        storage->configure(registry, metadata);
    }

    void TearDown() override {
        delete registry;
        delete metadata;
        delete storage;
    }

    StorageModule* storage;
    StorageRegistry* registry;
    StorageRegistry* metadata;
    int int_key;
    int float_key;
    int buf_key;
    int test_tag;
    int test_tag2;

    int meta_int_key;
    int meta_float_key;

    void addNFloats(int N)
    {
        StorageEntry* entry;
        int size = storage->getNewEntries()->getSize();

        //Add 5 entries with increasing key valuse.
        for (int i = 1; i < N+1; i++)
        {
            entry = storage->createNewEntry();
            float f = 0.1 + i;
            entry->setValue(float_key, f);
            EXPECT_EQ(storage->getNewEntries()->getSize(), ++size) << "Size was not as expected";
        }
    }


    bool inOrder(StorageEntry* a, StorageEntry* b)
    {
        bool equalValues = (a->getFloatValue(float_key) == b->getFloatValue(float_key));
        bool aLessThanB = (a->getFloatValue(float_key) < b->getFloatValue(float_key));
        if (registry->getSortByOrder() == StorageRegistry::ASCENDING)
        {
            return (aLessThanB || equalValues);
        }
        else
        {
            return (!aLessThanB || equalValues);
        }
  
    }

    bool isSaveListInOrder()
    {
        std::unique_ptr<Iterator> itr = storage->getSavedEntries();

        // empty of single element lists are always sorted.
        if (itr->getSize() < 2)
        {
            return true;
        }
        
        StorageEntry *current, *next;
        current = itr->getNext();
        while (itr->hasNext())
        {
            next = itr->getNext();
            if (!inOrder(current, next))
            {
                return false;
            }
            current = next;
        }

        return true;
    }

    bool almostEqual(float a, float b)
    {
        return fabs(a - b) <= FLT_EPSILON;
    }

    bool contains(int i, std::vector<int> list)
    {
        bool found = false;
        for(int j: list)
        {
            if(i == j)
            {
                found = true;
                break;
            }
        }

        return found;
    }

};

TEST_F(StorageModuleTestFloat, listsEmptyOnInit)
{
    ASSERT_EQ(storage->getNewEntries()->getSize(), 0) << "newList not empty.";
    ASSERT_EQ(storage->getSavedEntries()->getSize(), 0) << "entryList not empty.";
}

TEST_F(StorageModuleTestFloat, createNewEntry)
{
    // check that the entries list is empty
    int size = storage->getNewEntries()->getSize();
    ASSERT_EQ(size, 0);

    // Create a new storage entry
    StorageEntry* entry = storage->createNewEntry();

    // check that the entries list has grown.
    EXPECT_EQ(storage->getNewEntries()->getSize(), size + 1);
}

TEST_F(StorageModuleTestFloat, testTagMethods)
{
    // Create a new storage entry
    StorageEntry* entry = storage->createNewEntry();

    GTEST_COUT << "Checking tag handles\n";
    // Check that storage has the right number of tags
    std::vector<int> tagHandles = storage->getListOfTagHandles();
    ASSERT_EQ(tagHandles.size(),2); //2 tags is registered in the setup of this test case

    // check that the tag list is empty
    GTEST_COUT << "Checking tag list\n";
    std::vector<int> tags = entry->getTagList();
    ASSERT_EQ(tags.size(),0);
}

TEST_F(StorageModuleTestFloat, saveEntryThrowOnMetadata)
{
    // Simple case: test metadata save failure
    StorageEntry& meta_entry = storage->getMetadata();
    EXPECT_ANY_THROW(storage->saveEntry(&meta_entry));
}

TEST_F(StorageModuleTestFloat, saveEntryFloatKey)
{
    // Starting point
    int size = storage->getSavedEntries()->getSize();
    EXPECT_EQ(size, 0) << "Initial size not 0";

    StorageEntry* entry;

    //Add 5 entries with increasing key values
    //Make sure they are stored in order
    GTEST_COUT << "Adding 5 float entries (increasing values)\n";
    try
    {
        for (int i = 1; i < 6; i++)
        {
            entry = storage->createNewEntry();
            float f = 0.1 + i;
            entry->setValue(float_key, f);
            storage->saveEntry(entry);
            EXPECT_EQ(storage->getSavedEntries()->getSize(), ++size) << "Size was not as expected";
            EXPECT_TRUE(isSaveListInOrder()) << "Save list was out of order";
        }
    }
    catch(RuntimeException e)
    {
        FAIL() <<"Exception when adding float entries: " << e.getReason();
    }


    // add 5 entries with decreasing key valuse.
    // check that they are iserted in order.
    GTEST_COUT << "Adding 5 float entries (decreasing values)\n";
    try
    {
        for (int i = 10; i > 5; i--)
        {
            size = storage->getSavedEntries()->getSize();
            entry = storage->createNewEntry();
            float f = 0.1 + i;
            entry->setValue(float_key, f);
            storage->saveEntry(entry);
            EXPECT_EQ(storage->getSavedEntries()->getSize(), size + 1) << "Size was not as expected (decreasing values)";
            EXPECT_TRUE(isSaveListInOrder()) << "Save list was out of order (decreasing values)";
        }
    }
    catch(RuntimeException e)
    {
        FAIL() <<"Exception when adding more float entries: " << e.getReason();
    }


    //Check that the int values are correct
    GTEST_COUT << "Checking that float values are correct\n";
    std::unique_ptr<Iterator> allEntries = storage->getSavedEntries();
    int count = 11;
    while(allEntries->hasNext())
    {
        count--;
        entry = allEntries->getNext();
        float val = entry->getFloatValue(float_key);
        EXPECT_TRUE(almostEqual(val, count + 0.1)) << "Float value was not as expected: got " << val << ", expected " << count + 0.1;
    }
    
    EXPECT_EQ(count, 1) << "Wrong number of saved entries";

    GTEST_COUT << "Adding 5 float entries (duplicate values)\n";
    for (int i = 1; i < 6; i++)
    {
        size = storage->getSavedEntries()->getSize();
        entry = storage->createNewEntry();
        float f = 0.1 + i;
        entry->setValue(float_key, f);
        storage->saveEntry(entry);
        EXPECT_EQ(storage->getSavedEntries()->getSize(), size + 1) << "Size was not as expected";
        EXPECT_TRUE(isSaveListInOrder()) << "Save list was out of order";
    }
}

TEST_F(StorageModuleTestFloat, saveEntryBufferKey)
{
    // Starting point
    int size = storage->getSavedEntries()->getSize();
    EXPECT_EQ(size, 0);
    char* buf;
    StorageEntry* entry;

    // add 5 entries with increasing key valuse.
    // keys will be 1.1 to 5.1
    // buffer[9] will be set to 1 to 5
    // check that they are iserted in order.
    for (int i = 1; i < 6; i++)
    {
        size = storage->getSavedEntries()->getSize();
        entry = storage->createNewEntry();
        float f = 0.1 + i;
        entry->setValue(float_key, f);
        buf = entry->allocateBuffer(buf_key, 10);
        buf[9] = i;
        storage->saveEntry(entry);
        EXPECT_EQ(storage->getSavedEntries()->getSize(), size + 1);
        EXPECT_TRUE(isSaveListInOrder());
    }

    //Check that the buffer values are correct
    std::unique_ptr<Iterator> allEntries = storage->getSavedEntries();
    int count = 6;
    while(allEntries->hasNext())
    {
        entry = allEntries->getNext();
        count--;
        int bufSize = entry->getBufferSize(buf_key);
        EXPECT_EQ(bufSize, 10) << "Buffer size not as expected";
        char* buf = entry->getBufferPointer(buf_key);
        int bufVal = (int) buf[9];
        GTEST_COUT << "ID=" << entry->getID() << ", key=" << entry->getFloatValue(float_key) << 
            ", bufVal=" << bufVal << ", count=" << count << "\n";
        EXPECT_EQ(count, bufVal) << "Buffer value not as expected";
    }

    EXPECT_EQ(count, 1) << "Wrong number of saved entries";

}

TEST_F(StorageModuleTestFloat, removeEntryThrowOnMetadata)
{
    // Simple case: test metadata save failure
    StorageEntry& meta_entry = storage->getMetadata();
    EXPECT_THROW(storage->removeEntry(&meta_entry), RuntimeException);
}

TEST_F(StorageModuleTestFloat, clearNewAndLocalEntries)
{
    addNFloats(50);
    std::unique_ptr<Iterator> allEntries = storage->getNewEntries();
    StorageEntry* entry;
    std::vector<int> savedIds;
    bool saveMe = false;
    for(int i=0; i<20; i++)
    {
        //Save every other new entry that is returned (up to 10 entries)
        ASSERT_TRUE(allEntries->hasNext());
        saveMe = !saveMe;
        if(saveMe)
        {
            entry = allEntries->getNext();
            storage->saveEntry(entry);
            savedIds.push_back(entry->getID());
        }
    }

    //Make sure the entries that will be saved are correct
    std::unique_ptr<Iterator> toBeSavedEntries = storage->getNewEntriesThatWillBeSaved();
    int count = 0;
    while(toBeSavedEntries->hasNext())
    {
        count++;
        entry = toBeSavedEntries->getNext();
        bool found = false;
        for(int i=0; i<savedIds.size(); i++)
        {
            int id = entry->getID();
            if(id == savedIds[i])
            {
                found = true;
                break;
            }
        }
        ASSERT_TRUE(found) << "To be saved entry did not have correct id";
    }

    storage->clearNewAndLocalEntries(); //This deletes the unsaved entries

    ASSERT_EQ(storage->getSavedEntries()->getSize(), savedIds.size()) << "getSavedEntries size not as expected";
    ASSERT_EQ(storage->getNewEntries()->getSize(), 0) << "getNewEntries size not as expected";

    //Now retrieve the saved entries and make sure they are correct
    std::unique_ptr<Iterator> savedEntries = storage->getSavedEntries();
    count = 0;
    while(savedEntries->hasNext())
    {
        count++;
        entry = savedEntries->getNext();
        bool found = false;
        for(int i=0; i<savedIds.size(); i++)
        {
            int id = entry->getID();
            if(id == savedIds[i])
            {
                found = true;
                break;
            }
        }
        ASSERT_TRUE(found) << "Saved entry did not have correct id";
    }
}

TEST_F(StorageModuleTestFloat, removeEntry)
{
    // Starting point
    int size = storage->getSavedEntries()->getSize();
    EXPECT_EQ(size, 0);
    StorageEntry* entry;

    std::vector<StorageEntry*> entries;
    // add 10 entries to the save list.
    for (int i = 1; i < 10; i++)
    {
        entry = storage->createNewEntry();
        entries.push_back(entry);
        float f = 0.1 + i;
        entry->setValue(float_key, f);
        storage->saveEntry(entry);
    }

    // remove entries and ensure that they are actually gone.
    while (entries.size() > 0)
    {
        entry = entries.back();
        entries.pop_back();
        size = storage->getSavedEntries()->getSize();
        storage->removeEntry(entry);
        entry = nullptr;
        storage->clearNewAndLocalEntries(); //remove doesn't take effect until this is called
        EXPECT_EQ(storage->getSavedEntries()->getSize(), size - 1) << "Storage size was not as expected";
    }

    EXPECT_EQ(storage->getSavedEntries()->getSize(), 0) << "Final storage size was not as expected";

    //Now add some more entries
    addNFloats(50);
    std::unique_ptr<Iterator> allEntries = storage->getNewEntries();
    std::vector<StorageEntry*> savedEntries;
    bool saveMe = false;
    for(int i=0; i<20; i++)
    {
        //Save every other new entry that is returned (up to 10 entries)
        ASSERT_TRUE(allEntries->hasNext());
        saveMe = !saveMe;
        if(saveMe)
        {
            entry = allEntries->getNext();
            storage->saveEntry(entry);
            savedEntries.push_back(entry);
        }
    }

    //This removes the non-saved entries
    storage->clearNewAndLocalEntries();
    ASSERT_EQ(storage->getSavedEntries()->getSize(), savedEntries.size()) << "getSavedEntries size not as expected";

    //Now delete the first 5 saved entries
    for(int i=0; i<5; i++)
    {
        storage->removeEntry(savedEntries[i]);
    }
    
    //This actually deletes the entries
    storage->clearNewAndLocalEntries();
    ASSERT_EQ(storage->getSavedEntries()->getSize(), savedEntries.size() - 5) << "getSavedEntries size not as expected after removal";

    //Now make sure the right entries are left
    std::unique_ptr<Iterator> allEntries2 = storage->getSavedEntries();
    for(int i=allEntries2->getSize()-1; i>=0; i--)
    {
        StorageEntry* e = allEntries2->getNext();
        StorageEntry* expectedEntry = savedEntries[i+5];
        ASSERT_EQ(e->getID(), expectedEntry->getID()) << "savedEntries not as expected";
    }

}

TEST_F(StorageModuleTestFloat, removeWithoutClear)
{
    // Starting point
    int size = storage->getSavedEntries()->getSize();
    EXPECT_EQ(size, 0);
    StorageEntry* entry;

    std::vector<StorageEntry*> entries;
    // add 3 entries to the save list.
    for (int i = 1; i < 4; i++)
    {
        entry = storage->createNewEntry();
        entries.push_back(entry);
        float f = 0.1 + i;
        entry->setValue(float_key, f);
        entry->setValue(int_key, i);
        storage->saveEntry(entry);
    }
     //We should have 3 
    EXPECT_EQ(storage->getSavedEntries()->getSize(),3);

    //Now remove the first one
    entry = storage->getSavedEntries()->getNext();
    storage->removeEntry(entry);

    //This does the actual delete
    storage->clearNewAndLocalEntries();

    //Make sure there are two entries and they are the right ones
    std::unique_ptr<Iterator> entryList = storage->getSavedEntries();
    EXPECT_EQ(entryList->getSize(), 2);
    EXPECT_EQ(entryList->getNext()->getIntValue(int_key), 2);
    EXPECT_EQ(entryList->getNext()->getIntValue(int_key), 1);
}

TEST_F(StorageModuleTestFloat, tagEntry)
{
    // Starting point
    int size = storage->getSavedEntries()->getSize();
    ASSERT_EQ(size, 0);
    StorageEntry* entry1;
    StorageEntry* entry2;
    StorageEntry* entry3;
    std::vector<int> idList;

    GTEST_COUT << "Adding initial entries\n";
    addNFloats(6);
    ASSERT_EQ(storage->getNewEntries()->getSize(), 6) << "Storage size was not as expected";

    std::unique_ptr<Iterator> entries = storage->getNewEntries();
    for(int i=0; i<3; i++)
    {
        entries->getNext();
    }

    GTEST_COUT << "Tagging entries\n";
    //tag the 4th entry (without saving first)
    ASSERT_TRUE(entries->hasNext());
    entry1 = entries->getNext();
    entry1->addTag(test_tag);
    idList.push_back(entry1->getID());

    //save and tag the 5th entry
    ASSERT_TRUE(entries->hasNext());
    entry2 = entries->getNext();
    storage->saveEntry(entry2);
    entry2->addTag(test_tag);
    idList.push_back(entry2->getID());
    GTEST_COUT << entry2->getID() << " was saved and then tagged\n";

    //tag and save the 6th entry (order is opposite from the 5th one)
    ASSERT_TRUE(entries->hasNext());
    entry3 = entries->getNext();
    entry3->addTag(test_tag);
    storage->saveEntry(entry3);
    idList.push_back(entry3->getID());
    GTEST_COUT << entry3->getID() << " was tagged and then saved\n";

    GTEST_COUT << "Checking that entries are on the tagged list\n";
    //Check that all 3 entries are on the new tagged list
    std::unique_ptr<Iterator> newTaggedEntries = storage->getNewEntriesByTag(test_tag);
    ASSERT_EQ(newTaggedEntries->getSize(),3) << "Wrong number of newly tagged entries";
    //Make sure they are the right entries
    for(int i=0; i<3; i++)
    {
        ASSERT_TRUE(contains(newTaggedEntries->getNext()->getID(), idList)) << "getNewEntriesByTag list has unexpected entry id for index: " << i;
    }

    
    //Remove this entry1 as it is is about to be deleted
    remove(idList.begin(),idList.end(),entry1->getID());

    GTEST_COUT << "Calling clearNewAndLocalEntries\n";
    storage->clearNewAndLocalEntries();

    GTEST_COUT << "Checking that the saved entries are there after clearing\n";
    //Make sure they are there after clearing new entries and tags
    //Check for them on the entry list
    std::unique_ptr<Iterator> savedEntries = storage->getSavedEntries();
    ASSERT_EQ(savedEntries->getSize(),2) << "Wrong number of total entries after clearing";
    for(int i=0; i<2; i++)
    {
        StorageEntry* nextEntry = savedEntries->getNext();
        ASSERT_NE(nullptr, nextEntry);
        ASSERT_TRUE(contains(nextEntry->getID(), idList)) << "getSavedEntries list has unexpected entry id for index: " << i;
    }

    //Check for them on the tag list
    GTEST_COUT << "Checking that tagged entries are on the tag list after clearing\n";
    std::unique_ptr<Iterator> taggedEntries = storage->getSavedEntriesByTag(test_tag);
    ASSERT_EQ(taggedEntries->getSize(),2) << "Wrong number of tagged entries after clearing";
    for(int i=0; i<2; i++)
    {
        StorageEntry* nextEntry = taggedEntries->getNext();
        GTEST_COUT << "Entry " << nextEntry->getID() << " is on the tag list";
        ASSERT_NE(nullptr, nextEntry);
        ASSERT_TRUE(contains(nextEntry->getID(), idList)) << "getSavedEntriesByTag list has unexpected entry id for index: " << i;

        //Test the other tag handling methods
        ASSERT_TRUE(nextEntry->hasTag(test_tag));
        std::vector<int> tList = nextEntry->getTagList();
        ASSERT_EQ(tList.size(),1);
        ASSERT_EQ(tList[0],test_tag);
    }

    GTEST_COUT << "Deleting a tagged entry\n";
    //Now delete a tagged entry
    remove(idList.begin(),idList.end(),entry2->getID());
    storage->removeEntry(entry2);
    storage->clearNewAndLocalEntries(); //delete takes effect upon clear
  
    GTEST_COUT << "Checking that deletion worked correctly\n";
    //Make sure it's gone from the both the entry list and the tagged list
    std::unique_ptr<Iterator> savedEntries2 = storage->getSavedEntries();
    ASSERT_EQ(savedEntries2->getSize(),1) << "Wrong number of total entries after deletion";
    for(int i=0; i<1; i++)
    {
        StorageEntry* nextEntry = savedEntries2->getNext();
        ASSERT_NE(nullptr, nextEntry);
        ASSERT_TRUE(contains(nextEntry->getID(), idList)) << "getSavedEntries (after remove) has unexpected entry id for index: " << i;
    }

    std::unique_ptr<Iterator> taggedEntries2 = storage->getSavedEntriesByTag(test_tag);
    ASSERT_EQ(taggedEntries2->getSize(),1) << "Wrong number of tagged entries after deletion";
    for(int i=0; i<1; i++)
    {
        StorageEntry* nextEntry = taggedEntries2->getNext();
        ASSERT_NE(nullptr, nextEntry);
        ASSERT_TRUE(contains(nextEntry->getID(), idList)) << "getSavedEntriesByTag (after remove) has unexpected entry id for index: " << i;
    }

    //Now add and save a new entry, and make sure it gets on the tag list too
    GTEST_COUT << "Now adding and saving one more, and tagging it after save\n";
    StorageEntry* newEntry = storage->createNewEntry();
    storage->saveEntry(newEntry);

    storage->clearNewAndLocalEntries();

    newEntry->addTag(test_tag);
    idList.push_back(newEntry->getID());

    std::unique_ptr<Iterator> taggedEntries3 = storage->getSavedEntriesByTag(test_tag);
    ASSERT_EQ(taggedEntries3->getSize(),2) << "Wrong number of tagged entries after adding another one";
    for(int i=0; i<2; i++)
    {
        StorageEntry* nextEntry = taggedEntries3->getNext();
        ASSERT_NE(nullptr, nextEntry);
        ASSERT_TRUE(contains(nextEntry->getID(), idList)) << "getSavedEntriesByTag (after adding another one) has unexpected entry id for index: " << i;
    }

}

TEST_F(StorageModuleTestFloat, untagEntry)
{
    // Starting point
    int size = storage->getSavedEntries()->getSize();
    ASSERT_EQ(size, 0);
    std::vector<int> taggedIdList;

    std::vector<StorageEntry*> entries;
    StorageEntry* entry;
    // add 10 entries to the save list, and tag every other one
    for (int i = 1; i <= 10; i++)
    {
        entry = storage->createNewEntry();
        entries.push_back(entry);
        float f = 0.1 + i;
        entry->setValue(float_key, f);
        storage->saveEntry(entry);
        if(i % 2 == 0)
        {
            entry->addTag(test_tag);
            taggedIdList.push_back(entry->getID());
            ASSERT_TRUE(entry->hasTag(test_tag));
        }
    }

    std::unique_ptr<Iterator> newTaggedEntries = storage->getNewEntriesByTag(test_tag);
    std::unique_ptr<Iterator> taggedEntries = storage->getSavedEntriesByTag(test_tag);
    ASSERT_EQ(newTaggedEntries->getSize(), 5) << "Wrong number of new tagged entries";
    ASSERT_EQ(taggedEntries->getSize(), 5) << "Wrong number of tagged entries";

    //Now untag the last one
    entry->removeTag(test_tag);
    remove(taggedIdList.begin(),taggedIdList.end(),entry->getID());
    std::unique_ptr<Iterator> newTaggedEntries2 = storage->getNewEntriesByTag(test_tag);
    std::unique_ptr<Iterator> taggedEntries2 = storage->getSavedEntriesByTag(test_tag);
    ASSERT_EQ(newTaggedEntries2->getSize(), 4) << "Wrong number of new tagged entries after untagging";
    ASSERT_EQ(taggedEntries2->getSize(), 4) << "Wrong number of tagged entries after untagging";
    ASSERT_FALSE(entry->hasTag(test_tag));

    //Make sure it's correct after clearNewAndLocalEntries
    storage->clearNewAndLocalEntries();
    std::unique_ptr<Iterator> newTaggedEntries3 = storage->getNewEntriesByTag(test_tag);
    std::unique_ptr<Iterator> taggedEntries3 = storage->getSavedEntriesByTag(test_tag);
    ASSERT_EQ(newTaggedEntries3->getSize(), 0) << "Wrong number of new tagged entries after clearing";
    ASSERT_EQ(taggedEntries3->getSize(), 4) << "Wrong number of tagged entries after clearing";

    //Make sure it's the correct entries that are tagged
    for(int i=0; i<4; i++)
    {
        StorageEntry* nextEntry = taggedEntries3->getNext();
        ASSERT_NE(nullptr, nextEntry);
        ASSERT_TRUE(contains(nextEntry->getID(), taggedIdList)) << "getSavedEntriesByTag (after remove) has unexpected entry id for index: " << i;
        ASSERT_TRUE(nextEntry->hasTag(test_tag));
    }
}

TEST_F(StorageModuleTestFloat, getSavedEntryByID)
{
       // Starting point
    int size = storage->getSavedEntries()->getSize();
    ASSERT_EQ(size, 0);
    std::vector<long> taggedIdList;
    std::vector<long> taggedIdList2;

    std::vector<StorageEntry*> entries;
    StorageEntry* entry;
    // add 10 entries to the save list, and tag every other one
    for (int i = 1; i <= 10; i++)
    {
        entry = storage->createNewEntry();
        entries.push_back(entry);
        entry->setValue(int_key, i);
        storage->saveEntry(entry);
        if(i % 2 == 0)
        {
            entry->addTag(test_tag);
            taggedIdList.push_back(entry->getID());
            GTEST_COUT << "TEST_TAG on entry " << entry->getID() << "\n";
        }
        if(i % 3 == 0)
        {
            entry->addTag(test_tag2);
            taggedIdList2.push_back(entry->getID());
            GTEST_COUT << "TEST_TAG2 on entry " << entry->getID() << "\n";
        }
    }

    GTEST_COUT << "Testing retrieving by ID\n";
    entry = storage->getSavedEntryByID(taggedIdList[2]);
    ASSERT_EQ(entry->getID(), taggedIdList[2]) << "getSavedEntryByID returned wrong value";

    entry = storage->getSavedEntryByID(taggedIdList[4]);
    ASSERT_EQ(entry->getID(), taggedIdList[4]) << "getSavedEntryByID returned wrong value";

    GTEST_COUT << "Testing retrieving by ID and tag\n";
    entry = storage->getSavedEntryByID(taggedIdList[1], test_tag);
    ASSERT_EQ(entry->getID(), taggedIdList[1]) << "getSavedEntryByID with tag returned wrong value";

    entry = storage->getSavedEntryByID(taggedIdList[3], test_tag);
    ASSERT_EQ(entry->getID(), taggedIdList[3]) << "getSavedEntryByID with tag returned wrong value";

    GTEST_COUT << "Testing tag exclusions\n";
    //Make sure that the get by tag property excludes tags as well
    //taggedIdList[0] should be tagged with test_tag but not test_tag2 (second entry)
    //taggedIdList2[0] should be tagged with only test_tag2 (third entry)
    //taggedIdList2[2] should be tagged with both tags (sixth entry)
    entry = storage->getSavedEntryByID(taggedIdList[0]);
    ASSERT_EQ(entry->getID(), taggedIdList[0]) << "Entry 2 not found";
    entry = storage->getSavedEntryByID(taggedIdList[0], test_tag);
    ASSERT_EQ(entry->getID(), taggedIdList[0]) << "Entry 2 not found with test_tag";
    entry = storage->getSavedEntryByID(taggedIdList[0], test_tag2);
    ASSERT_TRUE(nullptr == entry) << "Entry 2 not null with test_tag2";

    GTEST_COUT << "Testing tag exclusions for entry 3\n";
    entry = storage->getSavedEntryByID(taggedIdList2[0]);
    ASSERT_EQ(entry->getID(), taggedIdList2[0]) << "Entry 3 not found";
    entry = storage->getSavedEntryByID(taggedIdList2[0], test_tag2);
    ASSERT_EQ(entry->getID(), taggedIdList2[0]) << "Entry 3 not found with test_tag2";
    entry = storage->getSavedEntryByID(taggedIdList2[0], test_tag);
    ASSERT_TRUE(nullptr == entry) << "Entry 3 not null with test_tag";

    GTEST_COUT << "Testing tag exclusiong for entry 6\n";
    entry = storage->getSavedEntryByID(taggedIdList[2]);
    ASSERT_NE(nullptr, entry);
    GTEST_COUT << "ID=" << entry->getID() << "\n";
    ASSERT_EQ(entry->getID(), taggedIdList[2]) << "Entry 6 not found";
    entry = storage->getSavedEntryByID(taggedIdList[2], test_tag);
    ASSERT_NE(nullptr, entry);
    ASSERT_EQ(entry->getID(), taggedIdList[2]) << "Entry 6 not found with test_tag";
    entry = storage->getSavedEntryByID(taggedIdList[2], test_tag2);
    ASSERT_NE(nullptr, entry);
    ASSERT_EQ(entry->getID(), taggedIdList[2]) << "Entry 6 not null with test_tag2";

    GTEST_COUT << "Testing tags *after clearing*\n";
    storage->clearNewAndLocalEntries(); //Make sure these methods work correctly after clearing

    entry = storage->getSavedEntryByID(taggedIdList[2]);
    ASSERT_NE(nullptr, entry);
    ASSERT_EQ(entry->getID(), taggedIdList[2]) << "getSavedEntryByID returned wrong value (after clearing)";

    entry = storage->getSavedEntryByID(taggedIdList[4]);
    ASSERT_NE(nullptr, entry);
    ASSERT_EQ(entry->getID(), taggedIdList[4]) << "getSavedEntryByID returned wrong value (after clearing)";

    entry = storage->getSavedEntryByID(taggedIdList[1], test_tag);
    ASSERT_NE(nullptr, entry);
    ASSERT_EQ(entry->getID(), taggedIdList[1]) << "getSavedEntryByID with tag returned wrong value (after clearing)";

    entry = storage->getSavedEntryByID(taggedIdList[3], test_tag);
    ASSERT_NE(nullptr, entry);
    ASSERT_EQ(entry->getID(), taggedIdList[3]) << "getSavedEntryByID with tag returned wrong value (after clearing)";
 
     //Make sure that the get by tag property excludes tags as well
    //taggedIdList[0] should be tagged with test_tag but not test_tag2 (second entry)
    //taggedIdList2[0] should be tagged with only test_tag2 (third entry)
    //taggedIdList[3] should be tagged with both tags (sixth entry)
    entry = storage->getSavedEntryByID(taggedIdList[0]);
    ASSERT_NE(nullptr, entry);
    ASSERT_EQ(entry->getID(), taggedIdList[0]) << "Entry 2 not found";
    entry = storage->getSavedEntryByID(taggedIdList[0], test_tag);
    ASSERT_NE(nullptr, entry);
    ASSERT_EQ(entry->getID(), taggedIdList[0]) << "Entry 2 not found with test_tag";
    entry = storage->getSavedEntryByID(taggedIdList[0], test_tag2);
    ASSERT_TRUE(nullptr == entry) << "Entry 2 not null with test_tag2";

    entry = storage->getSavedEntryByID(taggedIdList2[0]);
    ASSERT_NE(nullptr, entry);
    ASSERT_EQ(entry->getID(), taggedIdList2[0]) << "Entry 3 not found";
    entry = storage->getSavedEntryByID(taggedIdList2[0], test_tag2);
    ASSERT_NE(nullptr, entry);
    ASSERT_EQ(entry->getID(), taggedIdList2[0]) << "Entry 3 not found with test_tag2";
    entry = storage->getSavedEntryByID(taggedIdList2[0], test_tag);
    ASSERT_TRUE(nullptr == entry) << "Entry 3 not null with test_tag";

    entry = storage->getSavedEntryByID(taggedIdList[2]);
    ASSERT_NE(nullptr, entry);
    ASSERT_EQ(entry->getID(), taggedIdList[2]) << "Entry 6 not found";
    entry = storage->getSavedEntryByID(taggedIdList[2], test_tag);
    ASSERT_NE(nullptr, entry);
    ASSERT_EQ(entry->getID(), taggedIdList[2]) << "Entry 6 not found with test_tag";
    entry = storage->getSavedEntryByID(taggedIdList[2], test_tag2);
    ASSERT_NE(nullptr, entry);
    ASSERT_EQ(entry->getID(), taggedIdList[2]) << "Entry 6 not null with test_tag2";
}

TEST_F(StorageModuleTestFloat, updatePrimaryKey)
{
    // Starting point
    int size = storage->getSavedEntries()->getSize();
    ASSERT_EQ(size, 0);

    //Add 50 elements with random keys
    for (int i = 1; i <= 50; i++)
    {
        StorageEntry* entry = storage->createNewEntry();
        float f = rand() / 100;
        entry->setValue(float_key, f);
        storage->saveEntry(entry);
    }

    //Clear new list
    storage->clearNewAndLocalEntries();

    //Make sure the list is in order
    EXPECT_TRUE(isSaveListInOrder()) << "List out of order after initial save";

    //Update the fitness on every 10th one
    std::unique_ptr<Iterator> allEntries = storage->getSavedEntries();
    int count = 0;
    while(allEntries->hasNext())
    {
        StorageEntry* e = allEntries->getNext();
        count++;
        if(count % 10 == 0)
        {
            float currVal = e->getFloatValue(float_key);
            e->setValue(float_key,currVal * 10);

            EXPECT_TRUE(isSaveListInOrder()) << "List out of order after updating entry " << count;
        }
    }

    EXPECT_TRUE(isSaveListInOrder()) << "List out of order after updating all entries";

    //Update the fitness on every 3rd one
    std::unique_ptr<Iterator> allEntries2 = storage->getSavedEntries();
    count = 0;
    while(allEntries2->hasNext())
    {
        StorageEntry* e = allEntries2->getNext();
        count++;
        if(count % 3 == 0)
        {
            float currVal = e->getFloatValue(float_key);
            e->setValue(float_key,currVal / 10);

            EXPECT_TRUE(isSaveListInOrder()) << "List out of order after updating entry " << count;
        }
    }

    EXPECT_TRUE(isSaveListInOrder()) << "List out of order after updating all entries again";

}

TEST_F(StorageModuleTestFloat, MetadataTest)
{
    StorageEntry& metadata = storage->getMetadata();
    float f = 12.34;

    metadata.setValue(meta_float_key, f);
    float x = metadata.getFloatValue(meta_float_key);
    ASSERT_EQ(x, f) << "VALUE NOT SET INITIALLY";

    //This should still be 45 with another copy of metadata
    StorageEntry& metadata2 = storage->getMetadata();
    x = metadata2.getFloatValue(meta_float_key);
    ASSERT_EQ(x, f) << "SET VALUE DOES NOT PERSIST";
}


}  // namespace
}  // namespace project
}  // namespace my
