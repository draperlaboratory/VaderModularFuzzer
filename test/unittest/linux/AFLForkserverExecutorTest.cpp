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
#include "AFLForkserverExecutor.hpp"
#include "../ModuleTestHelper.hpp"
#include "Logging.hpp"
#include <filesystem>

using namespace vmf;

#define GTEST_COUT std::cerr << "[          ] [ INFO ]"

class AFLForkserverExecutorTest : public ::testing::Test {
protected:
  AFLForkserverExecutorTest()
    {
        //This provides basic VMF logging, which is useful for debugging storage registration errors
        Logging::initConsoleLog();
    }

    void SetUp() override {
        testHelper = new ModuleTestHelper();
        //Construct module under test
        executor = new AFLForkserverExecutor("AFLForkserverExecutor");
        testHelper->addModule(executor);

        config = testHelper->getConfig();
        storage = testHelper->getStorage();
    }

    void TearDown() override {
        //Clear the output directory so there is a fresh one for each test
        std::filesystem::remove_all(OUTPUT_DIR);

        delete testHelper;
        //The ModuleTestHelper destructor will also delete any added modules
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
        hasNewCoverageTag = registry->registerTag("HAS_NEW_COVERAGE", StorageRegistry::READ_ONLY);
        testCaseKey = registry->registerKey("TEST_CASE", StorageRegistry::BUFFER, StorageRegistry::WRITE_ONLY);

        //Initialize everything using the ModuleTestHelper class
        try
        {
            testHelper->initializeModulesAndStorage();
        }
        catch(RuntimeException e)
        {
            FAIL() << "Storage initialization failed -- " << e.getReason();
        }

        //Module is now fully initialized and ready for further testing
    }

    std::string OUTPUT_DIR = "./unittest_output/";
    
    ModuleTestHelper* testHelper; //testHelper will destroy all of the modules when it is destroyed
    ExecutorModule* executor;
    TestConfigInterface* config;
    StorageModule* storage;

    //Storage fields that are read or written by this unit test
    int normalTag;
    int crashedTag;
    int hasNewCoverageTag;
    int testCaseKey;
};

TEST_F(AFLForkserverExecutorTest, basicExecTest)
{
    //Make sure the SUT exists before proceeding with additional tests
    std::vector<std::string> argv = {"../../../test/haystackSUT/haystack"};
    ASSERT_TRUE(std::filesystem::exists(argv[0])) << "SUT path does not exist (" << argv[0];
    GTEST_COUT << "Testing with SUT: " << argv[0] << "\n";

    try{
        config->setStringVectorParam("sutArgv",argv);
        setupExecutorTest();

        //Add a test case to storage (this should not crash)
        char buff1[] = {'A'};
        StorageEntry* entry1 = storage->createNewEntry();
        entry1->allocateAndCopyBuffer(testCaseKey,1,buff1);

        //Use this test case to calibrate
        GTEST_COUT << "Calibrating\n";
        std::unique_ptr<Iterator> newEntries = storage->getNewEntries();
        executor->runCalibrationCases(*storage, newEntries);

        //Now ask the executor to run the test case
        newEntries->resetIndex();
        GTEST_COUT << "Running test batch #1\n";
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

        //Now ask the executor to run the test cases
        GTEST_COUT << "Running test batch #2\n";
        std::unique_ptr<Iterator> newEntries2 = storage->getNewEntries();
        executor->runTestCases(*storage, newEntries2);

        //Check that they ran as expected
        ASSERT_TRUE(entry2->hasTag(normalTag));
        ASSERT_TRUE(entry3->hasTag(crashedTag));
        //Check that they have new coverage
        ASSERT_TRUE(entry2->hasTag(hasNewCoverageTag));
        ASSERT_TRUE(entry3->hasTag(hasNewCoverageTag));
    }
    catch(RuntimeException e)
    {
        FAIL() << "Exception thrown:" << e.getReason();
    }

}