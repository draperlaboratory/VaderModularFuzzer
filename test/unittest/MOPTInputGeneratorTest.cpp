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
#include "InputGeneratorModule.hpp"
#include "MOPTInputGenerator.hpp"
#include "StorageEntry.hpp"
#include "AFLFlipBitMutator.hpp"
#include "ModuleTestHelper.hpp"
#include "StorageModuleStructures.hpp"
#include "SaveCorpusOutput.hpp"

using namespace vmf;

#define GTEST_COUT std::cerr << "[          ] [ INFO ]"

class MOPTInputGenTest : public ::testing::Test {
protected:

    MOPTInputGenTest()
    {
        //This provides basic VMF logging, which is useful for debugging storage registration errors
        Logging::initConsoleLog();
    }

    void SetUp() override {
        testHelper = new ModuleTestHelper();

        // Construct module under test
        IG = new MOPTInputGenerator(ModuleName);
        testHelper->addModule(IG);

        config = testHelper->getConfig();
        storage = testHelper->getStorage();
        registry = testHelper->getRegistry();
        
        crashedTag = registry->registerTag("CRASHED", StorageRegistry::WRITE_ONLY);
        hungTag = registry->registerTag("HUNG", StorageRegistry::WRITE_ONLY);
        hasNewCoverage = registry->registerTag("HAS_NEW_COVERAGE", StorageRegistry::WRITE_ONLY);
        normalTag = registry->registerTag("RAN_SUCCESSFULLY", StorageRegistry::WRITE_ONLY);
        incompleteTag = registry->registerTag("INCOMPLETE", StorageRegistry::WRITE_ONLY);
        MOPTNewCoverageTag = registry->registerTag("MOPT_NEW_COVERAGE", StorageRegistry::WRITE_ONLY);

        testCaseKey = registry->registerKey("TEST_CASE", StorageRegistry::BUFFER, StorageRegistry::READ_WRITE);
        execTimeUsTag = registry->registerKey("EXEC_TIME_US", StorageRegistry::UINT, StorageRegistry::WRITE_ONLY);
        coverageCount = registry->registerKey("COVERAGE_COUNT", StorageRegistry::UINT, StorageRegistry::WRITE_ONLY);
        traceBitsKey = registry->registerKey("AFL_TRACE_BITS", StorageRegistry::BUFFER_TEMP, StorageRegistry::WRITE_ONLY);
        cmpLogMapKey = registry->registerKey("CMPLOG_MAP_BITS", StorageRegistry::BUFFER_TEMP, StorageRegistry::WRITE_ONLY);

        mutatorIdKey  = registry->registerKey("MUTATOR_ID", StorageRegistry::INT, StorageRegistry::READ_ONLY);
        testcaseParentIdKey = registry->registerKey("PARENT_ID", StorageRegistry::UINT, StorageRegistry::READ_ONLY);
        generationKey = registry->registerKey("GENERATION", StorageRegistry::UINT, StorageRegistry::READ_ONLY);
        numChildrenKey = registry->registerKey("NUM_CHILDREN", StorageRegistry::UINT, StorageRegistry::READ_ONLY);

        config->setOutputDir(".");
    }

    void TearDown() override {
        delete testHelper;
        //The ModuleTestHelper destructor will also delete any added modules
    }

    void Init() {
        //Initialize everything using the ModuleTestHelper class
        try
        {
            testHelper->initializeModulesAndStorage();
        }
        catch(RuntimeException e)
        {
            FAIL() << "Storage or module initialization failed due to error -- " << e.getReason();
        }
    }

    /* Custom assertion that verifies:
    - All seed testcases (with a parent ID of 0) are marked with an invalid mutator ID in its metadata
    */
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

    ModuleTestHelper* testHelper; // testHelper will destroy all of the modules when it is destroyed
    InputGeneratorModule* IG;
    TestConfigInterface* config;
    StorageModule* storage;
    StorageRegistry* registry;
    std::string ModuleName = "MOPTInputGenerator";

    // Storage fields that are read or written by this unit test
    int testCaseKey;
    int testcaseParentIdKey;
    int generationKey;
    int numChildrenKey;
    int mutatorIdKey;
    
    // Tags for testcase determination
    int normalTag;
    int MOPTNewCoverageTag;
    int crashedTag;
    int hungTag;
    int incompleteTag;
  
    int hasNewCoverage;
    int execTimeUsTag;
    int coverageCount;
    int traceBitsKey;
    int cmpLogMapKey;
};

/* Verify that IG can generate new testcases on a basic corpus */
TEST_F(MOPTInputGenTest, basicMutationTest)
{
    // Configure MOPT to work with a single mutator
    MutatorModule* mutator1 = new AFLFlipBitMutator("mutator1");
    testHelper->addModule(mutator1);
    config->addSubmodule(ModuleName,mutator1);

    // Initialize the testhelper
    Init();
    

    // calibrate the executors
    char buffCal[] = {'C','A','L'};
    StorageEntry* entryCal = storage->createNewEntry();
    entryCal->allocateAndCopyBuffer(testCaseKey,3, buffCal);
    entryCal->addTag(normalTag);
    storage->saveEntry(entryCal);
    std::unique_ptr<Iterator> newEntries = storage->getNewEntries();

    // Add some seed test cases to storage
    // These all need to be saved and marked with the normal tag in order to be used
    char buff1[] = {'V','M','F'};
    StorageEntry* entry1 = storage->createNewEntry();
    entry1->allocateAndCopyBuffer(testCaseKey,3, buff1);
    entry1->addTag(normalTag);
    storage->saveEntry(entry1);

    char buff2[] = {'T','E','S','T'};
    StorageEntry* entry2 = storage->createNewEntry();
    entry2->allocateAndCopyBuffer(testCaseKey,4,buff2);
    entry2->addTag(normalTag);
    storage->saveEntry(entry2);

    // Now test the module
    IG->addNewTestCases(*storage);

    // Verify that the mutators are properly attributed
    verifyMutatorAttribution();
}
