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
#include "FridaExecutor.hpp"
#include "../ModuleTestHelper.hpp"
#include "Logging.hpp"
#include <filesystem>


using namespace vmf;

#define GTEST_COUT std::cerr << "[          ] [ INFO ]"

class FridaExecutorTest : public ::testing::Test {
protected:
  FridaExecutorTest()
    {
        //This provides basic VMF logging, which is useful for debugging storage registration errors
        Logging::initConsoleLog();
    }

    void SetUp() override {
        testHelper = new ModuleTestHelper();
        //Construct module under test
        executor = new FridaExecutor("FridaExecutor");
        testHelper->addModule(executor);

        config = testHelper->getConfig();
        storage = testHelper->getStorage();
    }

    void TearDown() override {
        //The ModuleTestHelper destructor will also delete any added modules
        delete testHelper;

        //Clear the output directory so there is a fresh one for each test
        std::filesystem::remove_all(OUTPUT_DIR);
    }

    //Module specific test setup
    void setupExecutorTest()
    {
        //This module requires the output directory parameter
        config->setOutputDir(OUTPUT_DIR);

        //Register for relevant storage handles that we need to read or write within the unit test
        //(the module's registerStorageNeeds method is called automatically by the ModuleTestHelper)
        StorageRegistry* registry = testHelper->getRegistry();
        normalTag = registry->registerTag("RAN_SUCCESSFULLY", StorageRegistry::READ_ONLY);
        crashedTag = registry->registerTag("CRASHED", StorageRegistry::READ_ONLY);
        hungTag = registry->registerTag("HUNG", StorageRegistry::READ_ONLY);
        hasNewCoverageTag = registry->registerTag("HAS_NEW_COVERAGE", StorageRegistry::READ_ONLY);
        testCaseKey = registry->registerKey("TEST_CASE", StorageRegistry::BUFFER, StorageRegistry::WRITE_ONLY);

        //Make sure the SUT exists before proceeding with additional tests
        //assume we are running from build_artifacts. 
        std::vector<std::string> argv;

        if ( std::filesystem::exists("vmf_install/test/haystackSUT/haystack_libfuzzer.exe" ) ) {
            argv.emplace_back( "vmf_install/test/haystackSUT/haystack_libfuzzer.exe" );
        }
        else if ( std::filesystem::exists("../test/haystackSUT/haystack_libfuzzer.exe" ) ) {
            argv.emplace_back( "../test/haystackSUT/haystack_libfuzzer.exe" );
        } else {
            GTEST_COUT << "Cannot find exe from " << std::filesystem::current_path();
            GTEST_FAIL();
        }
        GTEST_COUT << "Testing with SUT: " << argv[0] << "\n";

        config->setStringVectorParam(executor->getModuleName(), "sutArgv",argv);

        config->dump();
        
        //Initialize everything using the ModuleTestHelper class
        try
        {
            testHelper->initializeModulesAndStorage();
        }
        catch(RuntimeException e)
        {
            FAIL() << "Storage initialization failed -- " << e.getReason();
        }

        config->dump();
        //Module is now fully initialized and ready for further testing
    }

    std::string OUTPUT_DIR = "./unittest_output/";
    
    ModuleTestHelper* testHelper; //testHelper will destroy all of the modules when it is destroyed
    FridaExecutor* executor;
    TestConfigInterface* config;
    StorageModule* storage;

    //Storage fields that are read or written by this unit test
    int normalTag;
    int crashedTag;
    int hungTag;
    int hasNewCoverageTag;
    int testCaseKey;
};

TEST_F(FridaExecutorTest, basicExecTest)
{
    try{
        config->setBoolParam(executor->getModuleName(),"debugLog",true);

        setupExecutorTest();

        /* Run two test batch's 10 times to stress restart (on crash+hang) */
        for( auto i = 0; i < 10; i++ ) {
            //Add a test case to storage (this should not crash)
            char buff1[] = {'A'};
            StorageEntry* entry1 = storage->createNewEntry();
            entry1->allocateAndCopyBuffer(testCaseKey,1,buff1);

            std::unique_ptr<Iterator> newEntries = storage->getNewEntries();

            //Now ask the executor to run the test case
            newEntries->resetIndex();
            executor->runTestCases(*storage, newEntries);

            //Check that it ran normally
            ASSERT_TRUE(entry1->hasTag(normalTag));

            //Clear the new test cases
            GTEST_COUT << "Clearing new and local entries\n";
            entry1 = nullptr;
            storage->clearNewAndLocalEntries();

            //Add a test case with slightly more coverage to storage (this should not crash)
            char buff2[] = {'n','e'};
            StorageEntry* entry2 = storage->createNewEntry();
            entry2->allocateAndCopyBuffer(testCaseKey,2,buff2);

            //Add a test case that should crash
            char buff3[] = {'n','e','e','d','l','e'};
            StorageEntry* entry3 = storage->createNewEntry();
            entry3->allocateAndCopyBuffer(testCaseKey,6,buff3);

            //Add a test case that should have no new coverage and follow crashing cases
            char buff4[] = {'f','o'};
            StorageEntry* entry4 = storage->createNewEntry();
            entry4->allocateAndCopyBuffer(testCaseKey,2,buff4);

            //Add a test case that should hang
            char buff5[] = {'n','e','e','d','l','e','H'};
            StorageEntry* entry5 = storage->createNewEntry();
            entry5->allocateAndCopyBuffer(testCaseKey,7,buff5);


            //Now ask the executor to run the test cases
            std::unique_ptr<Iterator> newEntries2 = storage->getNewEntries();
            executor->runTestCases(*storage, newEntries2);

            //Check that they ran as expected
            ASSERT_TRUE(entry2->hasTag(normalTag));
            ASSERT_TRUE(entry3->hasTag(crashedTag));
            ASSERT_TRUE(entry4->hasTag(normalTag));
            ASSERT_TRUE(entry5->hasTag(hungTag));
            //Check that they have new coverage
            if ( i == 0 ) {
                ASSERT_TRUE(entry2->hasTag(hasNewCoverageTag));
                ASSERT_TRUE(entry3->hasTag(hasNewCoverageTag));
                ASSERT_FALSE(entry4->hasTag(hasNewCoverageTag));
                ASSERT_TRUE(entry5->hasTag(hasNewCoverageTag));
            }
        }
    }
    catch(RuntimeException e)
    {
        FAIL() << "Exception thrown:" << e.getReason();
    }

}

TEST_F(FridaExecutorTest, sutRestartTest)
{
    try{
        int nGroup = 0;
        config->setBoolParam(executor->getModuleName(),"debugLog",true);
        config->setIntParam(executor->getModuleName(),"numTestsPerProcess",3);
        setupExecutorTest();

        //Add a test case to storage (this should not crash)
        char buff1[] = {'A'};
        StorageEntry* entry1 = storage->createNewEntry();
        entry1->allocateAndCopyBuffer(testCaseKey,1,buff1);

        //Add a test case with slightly more coverage to storage (this should not crash)
        char buff2[] = {'n','e'};
        StorageEntry* entry2 = storage->createNewEntry();
        entry2->allocateAndCopyBuffer(testCaseKey,2,buff2);

        //Add a test case that should crash
        char buff3[] = {'n','e','e'};
        StorageEntry* entry3 = storage->createNewEntry();
        entry3->allocateAndCopyBuffer(testCaseKey,sizeof(buff3),buff3);


        do { 
            std::unique_ptr<Iterator> newEntries = storage->getNewEntries();

            GTEST_COUT << "Running test batch...\n";
            executor->runTestCases(*storage, newEntries);
            /* No test should ever not be normal */
            ASSERT_TRUE(entry1->hasTag(normalTag));
            ASSERT_TRUE(entry2->hasTag(normalTag));
            ASSERT_TRUE(entry3->hasTag(normalTag));
            /* Ensure tag's are being reset correctly */
            entry1->removeTag(normalTag);
            entry2->removeTag(normalTag);
            entry3->removeTag(normalTag);
            GTEST_COUT << "Pass " << nGroup << " sutStarts: " << executor->GetNumTestProcessesUsed() << "\n";
            newEntries->resetIndex();
        } while( nGroup++ < 10 );
        // Executor will restart on last exit so there is one more than expected. 
        ASSERT_TRUE( (executor->GetNumTestProcessesUsed() == 11) );
    }
    catch(RuntimeException e)
    {
        FAIL() << "Exception thrown:" << e.getReason();
    }

}

TEST_F(FridaExecutorTest, coverageStability)
{
    try{
        int nGroup = 0;
        config->setBoolParam(executor->getModuleName(),"debugLog",true);
        config->setIntParam(executor->getModuleName(),"numTestsPerProcess",2);
        setupExecutorTest();

        //Add a test case to storage (this should not crash)
        char buff1[] = {'A'};
        StorageEntry* entry1 = storage->createNewEntry();
        entry1->allocateAndCopyBuffer(testCaseKey,1,buff1);

        //Add a test case to storage (this should not crash)
        char buff2[] = {'B'};
        StorageEntry* entry2 = storage->createNewEntry();
        entry2->allocateAndCopyBuffer(testCaseKey,1,buff2);

        std::unique_ptr<Iterator> newEntries = storage->getNewEntries();
        
        /* Run initial batch, expect first has new, second does not*/
        executor->runTestCases(*storage, newEntries);
        ASSERT_TRUE(entry1->hasTag(hasNewCoverageTag));
        ASSERT_FALSE(entry2->hasTag(hasNewCoverageTag));

        /* Remove tag on first, as we are going to run a bunch of batches (lots of restarts). 
           Verify that the tag better not get added back */
        entry1->removeTag(hasNewCoverageTag);
        newEntries->resetIndex();
        do { 
            executor->runTestCases(*storage, newEntries);
            ASSERT_FALSE(entry1->hasTag(hasNewCoverageTag));
            ASSERT_FALSE(entry2->hasTag(hasNewCoverageTag));
            newEntries->resetIndex();
        } while( nGroup++ < 20 );
    }
    catch(RuntimeException e)
    {
        FAIL() << "Exception thrown:" << e.getReason();
    }

}
