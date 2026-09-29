/* =============================================================================
 * Vader Modular Fuzzer (VMF)
 * Copyright (c) 2021-2026 The Charles Stark Draper Laboratory, Inc.
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
#include <set>
#include "gtest/gtest.h"
#include "GeneticAlgorithmInputGenerator.hpp"
#include "ModuleTestHelper.hpp"
#include "AFLFlipBitMutator.hpp"
#include "StorageModuleStructures.hpp"

using namespace vmf;

#define GTEST_COUT std::cerr << "[          ] [ INFO ]"

class GAInputGenTest : public ::testing::Test {
protected:

    GAInputGenTest()
    {
        //This provides basic VMF logging, which is useful for debugging storage registration errors
        Logging::initConsoleLog();
    }

    void SetUp() override {
        testHelper = new ModuleTestHelper();
        //Construct module under test
        GAInputGen = new GeneticAlgorithmInputGenerator(GAModuleName);
        testHelper->addModule(GAInputGen);

        config = testHelper->getConfig();
        storage = testHelper->getStorage();
        registry = testHelper->getRegistry();
        
        crashedTag = registry->registerTag("CRASHED", StorageRegistry::WRITE_ONLY);
        hungTag = registry->registerTag("HUNG", StorageRegistry::WRITE_ONLY);
        config->setOutputDir(".");
    }

    void TearDown() override {
        delete testHelper;
        //The ModuleTestHelper destructor will also delete any added modules
    }

    //Module specific test setup
    void add3MutatorSubmodulesAndInitEverything()
    {
        //Add mutators to testHelper
        MutatorModule* mutator1 = new AFLFlipBitMutator("mutator1");
        MutatorModule* mutator2 = new AFLFlipBitMutator("mutator2");
        MutatorModule* mutator3 = new AFLFlipBitMutator("mutator3");

        testHelper->addModule(mutator1);
        testHelper->addModule(mutator2);
        testHelper->addModule(mutator3);

        //Setup config data
        config->addSubmodule(GAModuleName,mutator1);
        config->addSubmodule(GAModuleName,mutator2);
        config->addSubmodule(GAModuleName,mutator3);

        //Register for relevant storage handles that we need to read or write within the unit test
        //(the module's registerStorageNeeds method is called automatically by the ModuleTestHelper)
        StorageRegistry* registry = testHelper->getRegistry();
        normalTag = registry->registerTag("RAN_SUCCESSFULLY", StorageRegistry::WRITE_ONLY);
        testCaseKey = registry->registerKey("TEST_CASE", StorageRegistry::BUFFER, StorageRegistry::READ_WRITE);
        mutatorIdKey = registry->registerKey("MUTATOR_ID", StorageRegistry::INT, StorageRegistry::READ_ONLY);

        //Initialize everything using the ModuleTestHelper class
        try
        {
            testHelper->initializeModulesAndStorage();
        }
        catch(RuntimeException e)
        {
            FAIL() << "Storage or module initialization failed due to error -- " << e.getReason();
        }

        //Module is now fully initialized and ready for further testing
    }
    
    /* Custom assertion that:
     - A storage entry has the expected generation
     - A storage entry has a mutator ID assigned within the valid range (including the <null> value)
     - A storage entry's parent ID is 0 if it's a seed
     - A storage entry's parent ID is set and it's parent recursively respects the rest of these assertions
    */
    void verifyAncestry(StorageModule *storage, StorageEntry *entry, unsigned int generation)
    {
        ASSERT_NE(entry, nullptr);
        ASSERT_NE(storage, nullptr);
        unsigned int id = entry->getID();
        int mutatorId = entry->getIntValue(mutatorIdKey);
        unsigned int parentId = entry->getUIntValue(testcaseParentIdKey);
        unsigned int gen = entry->getUIntValue(generationKey);
        unsigned int num_children = entry->getUIntValue(numChildrenKey);
        GTEST_COUT << "\tTestcase " << entry->getID() << 
            ": mutatorId=" << mutatorId <<
            " parent=" << parentId <<
            " num_children=" << num_children <<
            " generation=" << gen <<
            " (expected:" << gen << ")" <<
            std::endl;
        ASSERT_EQ(entry->getUIntValue(generationKey), generation);
        ASSERT_GE(mutatorId, -1);

        if (generation > 0) {
            ASSERT_GT(parentId, 0);
            verifyAncestry(storage, storage->getSavedEntryByID(parentId), generation - 1U);
        } else {
            ASSERT_EQ(parentId, 0);
        }
    }

    /* Custom assertion that:
    - All entries properly record the number of immediate children
    */
    void verifyChildCount()
    {
        std::unique_ptr<Iterator> allEntries = storage->getSavedEntries();
        StorageEntry *e;

        // construct the map of number of children observed and
        // number of children recorded in metadata
        // for all testcases
        while (allEntries->hasNext())
        {
            e = allEntries->getNext();
            GTEST_COUT << "\tTestcase " << e->getID() << 
                ": parent=" << e->getUIntValue(testcaseParentIdKey) <<
                " num_children=" << e->getUIntValue(numChildrenKey) <<
                " generation=" << e->getUIntValue(generationKey) <<
                std::endl;
            num_children_observed_map[e->getID()] = e->getUIntValue(numChildrenKey);
            num_children_map[e->getUIntValue(testcaseParentIdKey)].insert(e->getID());
        }

        std::unique_ptr<Iterator> newEntries = storage->getNewEntries();
        while (newEntries->hasNext())
        {
            e = newEntries->getNext();
            GTEST_COUT << "\tTestcase " << e->getID() << 
                ": parent=" << e->getUIntValue(testcaseParentIdKey) <<
                " num_children=" << e->getUIntValue(numChildrenKey) <<
                " generation=" << e->getUIntValue(generationKey) <<
                std::endl;
            num_children_observed_map[e->getID()] = e->getUIntValue(numChildrenKey);
            num_children_map[e->getUIntValue(testcaseParentIdKey)].insert(e->getID());
        }

        // For each testcase ID verify that:
        // - The number of children observed from the constructed ancestry matches what is recorded in the metadata
        unsigned int id;
        std::set<unsigned int> *children;
        for (auto &pair : num_children_observed_map)
        {
            id = pair.first;
            if (id > 0)
            {
                GTEST_COUT << "\tid:" << id << " children:{ ";
                for (auto &id : num_children_map[id])
                    std::cout << id << " ";
                std::cout << "}" << std::endl; 
                ASSERT_EQ(num_children_observed_map[id], num_children_map[id].size()) << "Mismatch for ID " << id;
            }
            else
                GTEST_COUT << "Skipping 'virtual' testcase 0" << std::endl;
        }
    }

    /* Custom assertion that all storage entries that are seed testcases are marked with an invalid mutator ID */
    void verifyMutatorAttribution()
    {
        std::unique_ptr<Iterator> allEntries = storage->getSavedEntries();
        StorageEntry *e;
        while (allEntries->hasNext())
        {
            e = allEntries->getNext();
            GTEST_COUT << "\tTestcase " << e->getID() << 
                ": parent=" << e->getUIntValue(testcaseParentIdKey) <<
                " num_children=" << e->getUIntValue(numChildrenKey) <<
                " generation=" << e->getUIntValue(generationKey) <<
                std::endl;
            if (e->getUIntValue(testcaseParentIdKey) == 0)
                ASSERT_EQ(e->getIntValue(mutatorIdKey), -1);
        }
    }

    ModuleTestHelper* testHelper; //testHelper will destroy all of the modules when it is destroyed
    InputGeneratorModule* GAInputGen;
    TestConfigInterface* config;    
    StorageModule* storage;
    StorageRegistry* registry;
    std::string GAModuleName = "GeneticAlgorithmInputGenerator";

    //Storage fields that are read or written by this unit test
    int normalTag;
    int testCaseKey;    
    int testcaseParentIdKey;
    int generationKey;
    int numChildrenKey;
    int mutatorIdKey;
    
    int crashedTag;
    int hungTag;

    // structure for verifying number of direct children in lineage metadata
    std::map<unsigned int, std::set<unsigned int>> num_children_map;
    std::map<unsigned int, unsigned int> num_children_observed_map;
};

TEST_F(GAInputGenTest, basicMutationTest)
{
    add3MutatorSubmodulesAndInitEverything();
    
    //Add some seed test cases to storage
    //These all need to be saved and marked with the normal tag in order to be used
    char buff1[] = {'V','M','F'};
    StorageEntry* entry1 = storage->createNewEntry();
    entry1->allocateAndCopyBuffer(testCaseKey,3,buff1);
    entry1->addTag(normalTag);
    storage->saveEntry(entry1);

    char buff2[] = {'T','E','S','T'};
    StorageEntry* entry2 = storage->createNewEntry();
    entry2->allocateAndCopyBuffer(testCaseKey,4,buff2);
    entry2->addTag(normalTag);
    storage->saveEntry(entry2);

    //This method must be called to make the entries above no longer new
    storage->clearNewAndLocalEntries();

    //Now test the module
    GAInputGen->addNewTestCases(*storage);

    //There should be 3 new entries in storage (one for each mutator)
    int size = storage->getNewEntries()->getSize();
    ASSERT_EQ(size,3);
}

/* Verify that GA IG correctly records metadata for generated testcases:
* - All generated testcases reference their parent's testcase ID
* - All generated testcases reference the mutator used to generate them
* - All generated testcases are marked with their "generation" (number of mutations away from a seed)
* - All generated testcases are marked with the number of immediate child testcases (one "generation" distance) derived from them
*/
TEST_F(GAInputGenTest, testcaseMetadataTest)
{
    // register keys for use with storage module analysis
    mutatorIdKey = registry->registerKey("MUTATOR_ID", StorageRegistry::INT, StorageRegistry::READ_ONLY);
    testcaseParentIdKey = registry->registerKey("PARENT_ID", StorageRegistry::UINT, StorageRegistry::READ_ONLY);
    generationKey = registry->registerKey("GENERATION", StorageRegistry::UINT, StorageRegistry::READ_ONLY);
    numChildrenKey = registry->registerKey("NUM_CHILDREN", StorageRegistry::UINT, StorageRegistry::READ_ONLY);
    add3MutatorSubmodulesAndInitEverything();
    
    //Add some seed test cases to storage
    //These all need to be saved and marked with the normal tag in order to be used
    std::vector<Testcase> testcases; testcases.resize(2);
    std::string buff1 = "VMF";
    testcases[0].buff = buff1;
    testcases[0].parentId = 0;
    testcases[0].generation = 0;
    testcases[0].numChildren = 1;
    testcases[0].mutatorId = -1;
    testcases[0].tags = {normalTag}; // testcase ID 1 (seed) with 1 child
    testcases[1].buff = "TEST";
    testcases[1].parentId = 1;
    testcases[1].generation = 1;
    testcases[1].numChildren = 0;
    testcases[1].mutatorId = 1;
    testcases[1].tags = {normalTag}; // testcase ID 2 (child of testcase ID 1), generation 1, no children
    
    //Add seed test cases to storage
    for (auto testcase : testcases)
    {
        //These all need to be saved and marked with the normal tag in order to be used
        std::vector<char> writable_copy(testcase.buff.begin(), testcase.buff.end());
        writable_copy.push_back('\0'); // Add the null terminator

        char* writable_ptr = writable_copy.data();
        StorageEntry* entry1 = storage->createNewEntry();

        entry1->allocateAndCopyBuffer(testCaseKey,testcase.buff.length(),writable_ptr);

        entry1->setValue(testcaseParentIdKey, testcase.parentId);
        entry1->setValue(generationKey, testcase.generation);
        entry1->setValue(numChildrenKey, testcase.numChildren);
        entry1->setValue(mutatorIdKey, testcase.mutatorId);
        for (auto &tag : testcase.tags) 
            entry1->addTag(tag);

        storage->saveEntry(entry1);
    }

    //This method must be called to make the entries above no longer new
    storage->clearNewAndLocalEntries(); 

    // Generate the new testcases
    GAInputGen->addNewTestCases(*storage);

    //There should be 3 new entries in storage (one for each mutator)
    std::unique_ptr<Iterator> interestingEntries = storage->getNewEntries();
    StorageEntry *entry;

    // Verify that all new testcases 
    bool atLeastOneInterestingEntry = false;
    while(interestingEntries->hasNext())
    {
        // TODO: Requires deep update to TestConfigInterface to generate and associate module IDs to names
        // ASSERT_STREQ(config->getModuleName(entry->getIntValue(mutatorIdKey)).c_str(), "AFLFlipBitMutator");
        entry = interestingEntries->getNext();
        verifyAncestry(storage, entry, 
            entry->getUIntValue(testcaseParentIdKey) == 1? 1 : 2); // if the given entry is derived from testcase ID 1, it should be a first generation testcase, otherwise it should be a second generation testcase
        atLeastOneInterestingEntry = true;
    }
    verifyChildCount();
    ASSERT_TRUE(atLeastOneInterestingEntry) << "No interesting entries were produced during testcase generation";

    verifyMutatorAttribution();
}
