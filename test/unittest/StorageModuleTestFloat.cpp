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
#include "gtest/gtest.h"
#include "SimpleStorage.hpp"
#include <string>
#include <cmath>

using namespace vader;

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

        metadata = new StorageRegistry();
        meta_int_key = metadata->registerKey(
            "META_INT",
            StorageRegistry::FLOAT,
            StorageRegistry::READ_WRITE
        );
        meta_float_key = registry->registerKey(
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
        std::unique_ptr<Iterator> itr = storage->getEntries();

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
    ASSERT_EQ(storage->getEntries()->getSize(), 0) << "entryList not empty.";
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

TEST_F(StorageModuleTestFloat, saveEntryThrowOnMetadata)
{
    // Simple case: test metadata save failure
    StorageEntry& meta_entry = storage->getMetadata();
    EXPECT_ANY_THROW(storage->saveEntry(&meta_entry));
}

TEST_F(StorageModuleTestFloat, saveEntryFloatKey)
{
    // Starting point
    int size = storage->getEntries()->getSize();
    EXPECT_EQ(size, 0) << "Initial size not 0";

    StorageEntry* entry;

    //Add 5 entries with increasing key values
    //Make sure they are stored in order
    GTEST_COUT << "Adding 5 float entries (increasing values)\n";
    for (int i = 1; i < 6; i++)
    {
        entry = storage->createNewEntry();
        float f = 0.1 + i;
        entry->setValue(float_key, f);
        storage->saveEntry(entry);
        EXPECT_EQ(storage->getEntries()->getSize(), ++size) << "Size was not as expected";
        EXPECT_TRUE(isSaveListInOrder()) << "Save list was out of order";
    }

    // add 5 entries with decreasing key valuse.
    // check that they are iserted in order.
    GTEST_COUT << "Adding 5 float entries (decreasing values)\n";
    for (int i = 10; i > 5; i--)
    {
        size = storage->getEntries()->getSize();
        entry = storage->createNewEntry();
        float f = 0.1 + i;
        entry->setValue(float_key, f);
        storage->saveEntry(entry);
        EXPECT_EQ(storage->getEntries()->getSize(), size + 1) << "Size was not as expected (decreasing values)";
        EXPECT_TRUE(isSaveListInOrder()) << "Save list was out of order (decreasing values)";
    }

    //Check that the int values are correct
    GTEST_COUT << "Checking that float values are correct\n";
    std::unique_ptr<Iterator> allEntries = storage->getEntries();
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
        size = storage->getEntries()->getSize();
        entry = storage->createNewEntry();
        float f = 0.1 + i;
        entry->setValue(float_key, f);
        storage->saveEntry(entry);
        EXPECT_EQ(storage->getEntries()->getSize(), size + 1) << "Size was not as expected";
        EXPECT_TRUE(isSaveListInOrder()) << "Save list was out of order";
    }
}

TEST_F(StorageModuleTestFloat, saveEntryBufferKey)
{
    // Starting point
    int size = storage->getEntries()->getSize();
    EXPECT_EQ(size, 0);
    char* buf;
    StorageEntry* entry;

    // add 5 entries with increasing key valuse.
    // keys will be 1.1 to 5.1
    // buffer[9] will be set to 1 to 5
    // check that they are iserted in order.
    for (int i = 1; i < 6; i++)
    {
        size = storage->getEntries()->getSize();
        entry = storage->createNewEntry();
        float f = 0.1 + i;
        entry->setValue(float_key, f);
        buf = entry->allocateBuffer(buf_key, 10);
        buf[9] = i;
        storage->saveEntry(entry);
        EXPECT_EQ(storage->getEntries()->getSize(), size + 1);
        EXPECT_TRUE(isSaveListInOrder());
    }

    //Check that the buffer values are correct
    std::unique_ptr<Iterator> allEntries = storage->getEntries();
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

TEST_F(StorageModuleTestFloat, clearNewEntriesAndTags)
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

    storage->clearNewEntriesAndTags(); //This deletes the unsaved entries

    ASSERT_EQ(storage->getEntries()->getSize(), savedIds.size()) << "getEntries size not as expected";
    ASSERT_EQ(storage->getNewEntries()->getSize(), 0) << "getNewEntries size not as expected";

    //Now retrieve the saved entries and make sure they are correct
    std::unique_ptr<Iterator> savedEntries = storage->getEntries();
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
    int size = storage->getEntries()->getSize();
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
        size = storage->getEntries()->getSize();
        storage->removeEntry(entry);
        entry = nullptr;
        storage->clearNewEntriesAndTags(); //remove doesn't take effect until this is called
        EXPECT_EQ(storage->getEntries()->getSize(), size - 1) << "Storage size was not as expected";
    }

    EXPECT_EQ(storage->getEntries()->getSize(), 0) << "Final storage size was not as expected";

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
    storage->clearNewEntriesAndTags();
    ASSERT_EQ(storage->getEntries()->getSize(), savedEntries.size()) << "getEntries size not as expected";

    //Now delete the first 5 saved entries
    for(int i=0; i<5; i++)
    {
        storage->removeEntry(savedEntries[i]);
    }
    
    //This actually deletes the entries
    storage->clearNewEntriesAndTags();
    ASSERT_EQ(storage->getEntries()->getSize(), savedEntries.size() - 5) << "getEntries size not as expected after removal";

    //Now make sure the right entries are left
    std::unique_ptr<Iterator> allEntries2 = storage->getEntries();
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
    int size = storage->getEntries()->getSize();
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
    EXPECT_EQ(storage->getEntries()->getSize(),3);

    //Now remove the first one
    entry = storage->getEntries()->getNext();
    storage->removeEntry(entry);

    //This does the actual delete
    storage->clearNewEntriesAndTags();

    //Make sure there are two entries and they are the right ones
    std::unique_ptr<Iterator> entryList = storage->getEntries();
    EXPECT_EQ(entryList->getSize(), 2);
    EXPECT_EQ(entryList->getNext()->getIntValue(int_key), 2);
    EXPECT_EQ(entryList->getNext()->getIntValue(int_key), 1);
}

TEST_F(StorageModuleTestFloat, tagEntry)
{
    // Starting point
    int size = storage->getEntries()->getSize();
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
    storage->tagEntry(entry1,test_tag);
    idList.push_back(entry1->getID());

    //save and tag the 5th entry
    ASSERT_TRUE(entries->hasNext());
    entry2 = entries->getNext();
    storage->saveEntry(entry2);
    storage->tagEntry(entry2,test_tag);
    idList.push_back(entry2->getID());

    //tag and save the 6th entry (order is opposite from the 5th one)
    ASSERT_TRUE(entries->hasNext());
    entry3 = entries->getNext();
    storage->tagEntry(entry3,test_tag);
    storage->saveEntry(entry3);
    idList.push_back(entry3->getID());


    GTEST_COUT << "Checking that entries are on the tagged list\n";
    //Check that both entries are on the tagged list
    std::unique_ptr<Iterator> newTaggedEntries = storage->getNewEntriesByTag(test_tag);
    ASSERT_EQ(newTaggedEntries->getSize(),3) << "Wrong number of newly tagged entries";
    //Make sure they are the right entries
    for(int i=0; i<3; i++)
    {
        ASSERT_TRUE(contains(newTaggedEntries->getNext()->getID(), idList)) << "getNewEntriesByTag list has unexpected entry id for index: " << i;
    }

    GTEST_COUT << "Calling clearNewEntriesAndTags\n";
    storage->clearNewEntriesAndTags();

    GTEST_COUT << "Checking that tagged entries are there after clearing\n";
    //Make sure they are there after clearing new entries and tags
    //Check for them on the entry list
    std::unique_ptr<Iterator> savedEntries = storage->getEntries();
    ASSERT_EQ(savedEntries->getSize(),3) << "Wrong number of total entries after clearing";
    for(int i=0; i<3; i++)
    {
        StorageEntry* nextEntry = savedEntries->getNext();
        ASSERT_NE(nullptr, nextEntry);
        ASSERT_TRUE(contains(nextEntry->getID(), idList)) << "getEntries list has unexpected entry id for index: " << i;
    }

    //Check for them on the tag list
    std::unique_ptr<Iterator> taggedEntries = storage->getEntriesByTag(test_tag);
    ASSERT_EQ(taggedEntries->getSize(),3) << "Wrong number of tagged entries after clearing";
    for(int i=0; i<3; i++)
    {
        StorageEntry* nextEntry = taggedEntries->getNext();
        ASSERT_NE(nullptr, nextEntry);
        ASSERT_TRUE(contains(nextEntry->getID(), idList)) << "getEntriesByTag list has unexpected entry id for index: " << i;
    
        //Test the other tag handling methods
        ASSERT_TRUE(storage->entryHasTag(nextEntry, test_tag));
        std::vector<int> tList = storage->getEntryTagList(nextEntry);
        ASSERT_EQ(tList.size(),1);
        ASSERT_EQ(tList[0],test_tag);
    }

    GTEST_COUT << "Deleting a tagged entry\n";
    //Now delete a tagged entry
    remove(idList.begin(),idList.end(),entry1->getID());
    storage->removeEntry(entry1);
    storage->clearNewEntriesAndTags(); //delete takes effect upon clear
  
    GTEST_COUT << "Checking that deletion worked correctly\n";
    //Make sure it's gone from the both the entry list and the tagged list
    std::unique_ptr<Iterator> savedEntries2 = storage->getEntries();
    ASSERT_EQ(savedEntries2->getSize(),2) << "Wrong number of total entries after deletion";
    for(int i=0; i<2; i++)
    {
        StorageEntry* nextEntry = savedEntries2->getNext();
        ASSERT_NE(nullptr, nextEntry);
        ASSERT_TRUE(contains(nextEntry->getID(), idList)) << "getEntries (after remove) has unexpected entry id for index: " << i;
    }

    GTEST_COUT << "Checking that tagged entries are on the tag list after clearing\n";
    std::unique_ptr<Iterator> taggedEntries2 = storage->getEntriesByTag(test_tag);
    ASSERT_EQ(taggedEntries2->getSize(),2) << "Wrong number of tagged entries after deletion";
    for(int i=0; i<2; i++)
    {
        StorageEntry* nextEntry = taggedEntries2->getNext();
        ASSERT_NE(nullptr, nextEntry);
        ASSERT_TRUE(contains(nextEntry->getID(), idList)) << "getEntriesByTag (after remove) has unexpected entry id for index: " << i;
    }
}

TEST_F(StorageModuleTestFloat, untagEntry)
{
    // Starting point
    int size = storage->getEntries()->getSize();
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
            storage->tagEntry(entry, test_tag);
            taggedIdList.push_back(entry->getID());
            ASSERT_TRUE(storage->entryHasTag(entry, test_tag));
        }
    }

    std::unique_ptr<Iterator> newTaggedEntries = storage->getNewEntriesByTag(test_tag);
    std::unique_ptr<Iterator> taggedEntries = storage->getEntriesByTag(test_tag);
    ASSERT_EQ(newTaggedEntries->getSize(), 5) << "Wrong number of new tagged entries";
    ASSERT_EQ(taggedEntries->getSize(), 5) << "Wrong number of tagged entries";

    //Now untag the last one
    storage->unTagEntry(entry, test_tag);
    remove(taggedIdList.begin(),taggedIdList.end(),entry->getID());
    std::unique_ptr<Iterator> newTaggedEntries2 = storage->getNewEntriesByTag(test_tag);
    std::unique_ptr<Iterator> taggedEntries2 = storage->getEntriesByTag(test_tag);
    ASSERT_EQ(newTaggedEntries2->getSize(), 4) << "Wrong number of new tagged entries after untagging";
    ASSERT_EQ(taggedEntries2->getSize(), 4) << "Wrong number of tagged entries after untagging";
    ASSERT_FALSE(storage->entryHasTag(entry, test_tag));

    //Make sure it's correct after clearNewEntriesAndTags
    storage->clearNewEntriesAndTags();
    std::unique_ptr<Iterator> newTaggedEntries3 = storage->getNewEntriesByTag(test_tag);
    std::unique_ptr<Iterator> taggedEntries3 = storage->getEntriesByTag(test_tag);
    ASSERT_EQ(newTaggedEntries3->getSize(), 0) << "Wrong number of new tagged entries after clearing";
    ASSERT_EQ(taggedEntries3->getSize(), 4) << "Wrong number of tagged entries after clearing";

    //Make sure it's the correct entries that are tagged
    for(int i=0; i<4; i++)
    {
        StorageEntry* nextEntry = taggedEntries3->getNext();
        ASSERT_NE(nullptr, nextEntry);
        ASSERT_TRUE(contains(nextEntry->getID(), taggedIdList)) << "getEntriesByTag (after remove) has unexpected entry id for index: " << i;
        ASSERT_TRUE(storage->entryHasTag(nextEntry, test_tag));
    }
}

TEST_F(StorageModuleTestFloat, getEntryByID)
{
    // Starting point
    int size = storage->getEntries()->getSize();
    ASSERT_EQ(size, 0);
    std::vector<long> taggedIdList;

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
            storage->tagEntry(entry, test_tag);
            taggedIdList.push_back(entry->getID());
        }
    }

    entry = storage->getEntryByID(taggedIdList[2]);
    ASSERT_EQ(entry->getID(), taggedIdList[2]) << "getEntryByID returned wrong value";

    entry = storage->getEntryByID(taggedIdList[4]);
    ASSERT_EQ(entry->getID(), taggedIdList[4]) << "getEntryByID returned wrong value";

    entry = storage->getEntryByID(taggedIdList[1], test_tag);
    ASSERT_EQ(entry->getID(), taggedIdList[1]) << "getEntryByID with tag returned wrong value";

    entry = storage->getEntryByID(taggedIdList[3], test_tag);
    ASSERT_EQ(entry->getID(), taggedIdList[3]) << "getEntryByID with tag returned wrong value";
 
}

TEST_F(StorageModuleTestFloat, updatePrimaryKey)
{
    // Starting point
    int size = storage->getEntries()->getSize();
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
    storage->clearNewEntriesAndTags();

    //Make sure the list is in order
    EXPECT_TRUE(isSaveListInOrder()) << "List out of order after initial save";

    //Update the fitness on every 10th one
    std::unique_ptr<Iterator> allEntries = storage->getEntries();
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
    std::unique_ptr<Iterator> allEntries2 = storage->getEntries();
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



}  // namespace
}  // namespace project
}  // namespace my