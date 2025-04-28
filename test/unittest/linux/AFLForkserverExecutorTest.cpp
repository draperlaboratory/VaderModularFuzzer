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
#include "gtest/gtest.h"
#include "AFLForkserverExecutor.hpp"
#include "ModuleTestHelper.hpp"
#include "Logging.hpp"
#include <filesystem>
#include <iostream>
#include <fstream>

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

        config = testHelper->getConfig();
        storage = testHelper->getStorage();

        //Check that haystack SUT exists
        std::string haystackPath = "../test/haystackSUT/haystack";
        std::vector<std::string> argv = {haystackPath};
        ASSERT_TRUE(std::filesystem::exists(argv[0])) << "SUT path does not exist (" << argv[0];
        GTEST_COUT << "Testing with SUT: " << argv[0] << "\n";
        config->setStringVectorParam(ExecModuleName,"sutArgv",argv);

        //Check that haystack persistent mode SUT exists. Uses version in unittest/inputs with special output for testing
        std::string haystackPersistPath = "../test/unittest/inputs/AFLForkserverExecutorTest/haystackSUT/haystack_AFL_persist";
        std::vector<std::string> argv_persist = {haystackPersistPath};
        ASSERT_TRUE(std::filesystem::exists(argv_persist[0])) << "SUT path does not exist (" << argv_persist[0];
        GTEST_COUT << "Testing with persistent SUT: " << argv_persist[0] << "\n";
        config->setStringVectorParam(ExecModuleNamePersistent,"sutArgv",argv_persist);
        config->setIntParam(ExecModuleNamePersistent,"timeoutInMs", 10000);

        //Check that haystack deferred initialization SUT exists
        std::string haystackDeferredPath = "../test/unittest/inputs/AFLForkserverExecutorTest/haystackSUT/haystack_AFL_deferred";
        std::vector<std::string> argv_deferred = {haystackDeferredPath};
        ASSERT_TRUE(std::filesystem::exists(argv_deferred[0])) << "SUT path does not exist (" << argv_deferred[0];
        GTEST_COUT << "Testing with deferred SUT: " << argv_deferred[0] << "\n";
        config->setStringVectorParam(ExecModuleNameDeferred,"sutArgv",argv_deferred);

        //Check that haystack shmem input delivery SUT exists
        std::string haystackShmemPath = "../test/haystackSUT/haystack_AFL_shmem";
        std::vector<std::string> argv_shmem = {haystackShmemPath};
        ASSERT_TRUE(std::filesystem::exists(argv_shmem[0])) << "SUT path does not exist (" << argv_shmem[0];
        GTEST_COUT << "Testing with shmem SUT: " << argv_shmem[0] << "\n";
        config->setStringVectorParam(ExecModuleNameShmem,"sutArgv",argv_shmem);
        config->setBoolParam(ExecModuleNameShmem, "debugLog", true);
        config->setBoolParam(ExecModuleNameShmem, "enableAFLDebug", true);

        /* Set up mime SUT default configuration */
        std::string mimePath = "../test/unittest/inputs/AFLForkserverExecutorTest/mimeSUT/mime";
        std::vector<std::string> argv_mime = {mimePath};
        ASSERT_TRUE(std::filesystem::exists(argv_mime[0])) << "SUT path does not exist (" << argv_mime[0];
        GTEST_COUT << "Testing default configuration with mime SUT: " << argv_mime[0] << "\n";
        config->setStringVectorParam(ExecModuleNameMime,"sutArgv",argv_mime);

        /* Set up mime SUT with file test case delivery, reuse mimePath */
        std::vector<std::string> argv_file = {mimePath, "@@"};
        GTEST_COUT << "Testing file-based test case delivery with mime SUT: " << argv_file[0] << "\n";
        config->setStringVectorParam(ExecModuleNameFile,"sutArgv",argv_file);

        /* Set up mime SUT interpreting configured exit code as crash */
        GTEST_COUT << "Testing custom exit code as crash with mime SUT: " << argv_mime[0] << "\n";
        config->setStringVectorParam(ExecModuleNameExitIsCrash,"sutArgv",argv_mime);
        config->setIntParam(ExecModuleNameExitIsCrash,"customExitCode",99);

        /* Set up mime to produce debug logs capturing stdout/stderr */
        GTEST_COUT << "Testing debug log generation with mime SUT: " << argv_mime[0] << "\n";
        config->setStringVectorParam(ExecModuleNameDebugLog,"sutArgv",argv_mime);
        config->setBoolParam(ExecModuleNameDebugLog, "debugLog", true);

        /* Set up mime SUT with legacy instrumentation */
        std::string mimeLegacyPath = "../test/unittest/inputs/AFLForkserverExecutorTest/mimeSUT/mime_legacy";
        std::vector<std::string> argv_legacy = {mimeLegacyPath};
        ASSERT_TRUE(std::filesystem::exists(argv_legacy[0])) << "SUT path does not exist (" << argv_legacy[0];
        GTEST_COUT << "Testing with legacy SUT: " << argv_legacy[0] << "\n";
        config->setStringVectorParam(ExecModuleNameLegacy,"sutArgv",argv_legacy);

        /* Set up mime SUT with ASAN */
        std::string mimeAsanPath = "../test/unittest/inputs/AFLForkserverExecutorTest/mimeSUT/mime_asan";
        std::vector<std::string> argv_asan = {mimeAsanPath};
        ASSERT_TRUE(std::filesystem::exists(argv_asan[0])) << "SUT path does not exist (" << argv_asan[0];
        GTEST_COUT << "Testing with asan SUT: " << argv_asan[0] << "\n";
        config->setStringVectorParam(ExecModuleNameAsan,"sutArgv",argv_asan);
        config->setBoolParam(ExecModuleNameAsan,"useASAN","true");
        
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

        //Core dump check is disabled so this test can run on CI/CD
        config->setBoolParam(ExecModuleName, "enableCoreDumpCheck",false);
        config->setBoolParam(ExecModuleNamePersistent, "enableCoreDumpCheck",false);
        config->setBoolParam(ExecModuleNameDeferred, "enableCoreDumpCheck",false);
        config->setBoolParam(ExecModuleNameShmem, "enableCoreDumpCheck",false);
        config->setBoolParam(ExecModuleNameMime, "enableCoreDumpCheck",false);
        config->setBoolParam(ExecModuleNameFile, "enableCoreDumpCheck",false);
        config->setBoolParam(ExecModuleNameDebugLog, "enableCoreDumpCheck",false);
        config->setBoolParam(ExecModuleNameExitIsCrash, "enableCoreDumpCheck",false);
        config->setBoolParam(ExecModuleNameLegacy, "enableCoreDumpCheck",false);
        config->setBoolParam(ExecModuleNameAsan, "enableCoreDumpCheck",false);

        //Register for relevant storage handles that we need to read or write within the unit test
        //(the module's registerStorageNeeds method is called automatically by the ModuleTestHelper)
        StorageRegistry* registry = testHelper->getRegistry();
        normalTag = registry->registerTag("RAN_SUCCESSFULLY", StorageRegistry::READ_ONLY);
        crashedTag = registry->registerTag("CRASHED", StorageRegistry::READ_ONLY);
        hungTag = registry->registerTag("HUNG", StorageRegistry::READ_ONLY);
        hasNewCoverageTag = registry->registerTag("HAS_NEW_COVERAGE", StorageRegistry::READ_ONLY);
        testCaseKey = registry->registerKey("TEST_CASE", StorageRegistry::BUFFER, StorageRegistry::WRITE_ONLY);
        execTimeKey = registry->registerKey("EXEC_TIME_US", StorageRegistry::UINT, StorageRegistry::WRITE_ONLY);

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

    std::string OUTPUT_DIR = "./unittest_output/";
    
    ModuleTestHelper* testHelper; //testHelper will destroy all of the modules when it is destroyed
    ExecutorModule* executor;
    ExecutorModule* executorPersistent;
    ExecutorModule* executorDeferred;
    TestConfigInterface* config;
    StorageModule* storage;
    std::string ExecModuleName = "AFLForkserverExecutor";
    std::string ExecModuleNamePersistent = "AFLForkserverExecutorPersistent";
    std::string ExecModuleNameDeferred = "AFLForkserverExecutorDeferred";
    std::string ExecModuleNameShmem = "AFLForkserverExecutorShmem";
    std::string ExecModuleNameMime = "AFLForkserverExecutorMime";
    std::string ExecModuleNameFile = "AFLForkserverExecutorFile";
    std::string ExecModuleNameDebugLog = "AFLForkserverExecutorDebugLog";
    std::string ExecModuleNameExitIsCrash = "AFLForkserverExecutorExitIsCrash";
    std::string ExecModuleNameLegacy = "AFLForkserverExecutorLegacy";
    std::string ExecModuleNameAsan = "AFLForkserverExecutorAsan";

    //Storage fields that are read or written by this unit test
    int normalTag;
    int crashedTag;
    int hungTag;
    int hasNewCoverageTag;
    int testCaseKey;
    int execTimeKey;
};

TEST_F(AFLForkserverExecutorTest, basicExecTest)
{

    try{

        //Create executor modules needed for this test
        executor = new AFLForkserverExecutor(ExecModuleName);
        testHelper->addModule(executor);

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

TEST_F(AFLForkserverExecutorTest, persistentExecTest)
{
    try{

        //Create executor modules needed for this test
        executorPersistent = new AFLForkserverExecutor(ExecModuleNamePersistent);
        testHelper->addModule(executorPersistent);

        setupExecutorTest();

        //Add a test case to storage (this should not crash)
        char buff1[] = {'A'};
        StorageEntry* entry1 = storage->createNewEntry();
        entry1->allocateAndCopyBuffer(testCaseKey,1,buff1);

        //Use this test case to calibrate
        GTEST_COUT << "Calibrating\n";
        std::unique_ptr<Iterator> newEntries = storage->getNewEntries();
        executorPersistent->runCalibrationCases(*storage, newEntries);

        //Now ask the executor to run the test case
        newEntries->resetIndex();
        GTEST_COUT << "Running test batch #1\n";
        executorPersistent->runTestCases(*storage, newEntries);

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
        executorPersistent->runTestCases(*storage, newEntries2);

        //Check that they ran as expected
        ASSERT_TRUE(entry2->hasTag(normalTag));
        ASSERT_TRUE(entry3->hasTag(crashedTag));
        //Check that they have new coverage
        ASSERT_TRUE(entry2->hasTag(hasNewCoverageTag));
        ASSERT_TRUE(entry3->hasTag(hasNewCoverageTag));

	//Lastly, check that these tests were run in the same process (persist mode is really working).
	//The persist SUT writes out the number of execs within a process to persist_out.txt, so
	//we inspect that.
        std::string tmp;
        std::ifstream persist_output("persist_out.txt", std::ios_base::in);
        getline(persist_output, tmp);
	int numExecsInProcess = std::stoi(tmp);

	GTEST_COUT << "Number of persist execs in one process:" << numExecsInProcess;
	ASSERT_TRUE(numExecsInProcess == 4);

	//Clean up persist out file
	std::filesystem::remove("persist_out.txt");
    }
    catch(RuntimeException e)
    {
        FAIL() << "Exception thrown:" << e.getReason();
    }
}


TEST_F(AFLForkserverExecutorTest, deferredExecTest)
{
    try{

	// The deferred test SUT uses a flag file to signal the deferred forkserver working.
	// Before the test runs, make sure it is not present (eg from a previous run).
	std::string flag_filename = "deferred_flag";
	if (std::filesystem::exists(flag_filename))
	{
	    std::filesystem::remove(flag_filename);
	}

	//Create executor modules needed for this test
        executorDeferred = new AFLForkserverExecutor(ExecModuleNameDeferred);
        testHelper->addModule(executorDeferred);

        setupExecutorTest();

        //Add a test case to storage (this should not crash)
        char buff1[] = {'A'};
        StorageEntry* entry1 = storage->createNewEntry();
        entry1->allocateAndCopyBuffer(testCaseKey,1,buff1);

        //Use this test case to calibrate
        GTEST_COUT << "Calibrating\n";
        std::unique_ptr<Iterator> newEntries = storage->getNewEntries();
        executorDeferred->runCalibrationCases(*storage, newEntries);

        //Now ask the executor to run the test case
        newEntries->resetIndex();
        executorDeferred->runTestCases(*storage, newEntries);

        //Check that it ran normally
        ASSERT_TRUE(entry1->hasTag(normalTag));

	//Make sure a flag was created
	ASSERT_TRUE(std::filesystem::exists(flag_filename));
	std::filesystem::remove(flag_filename);

        //Clear the new test cases
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
        executorDeferred->runTestCases(*storage, newEntries2);

        //Check that they ran as expected
        ASSERT_TRUE(entry2->hasTag(normalTag));
        ASSERT_TRUE(entry3->hasTag(crashedTag));
        //Check that they have new coverage
        ASSERT_TRUE(entry2->hasTag(hasNewCoverageTag));
        ASSERT_TRUE(entry3->hasTag(hasNewCoverageTag));

	//Lastly, make sure that only the first deferred_flag was created and there are no more now.
	//This shows that the fork point in the SUT moved to after where it creates the file.	
	bool noAdditionalFlagsCreated = !std::filesystem::exists(flag_filename);
	ASSERT_TRUE(noAdditionalFlagsCreated);
    }
    catch(RuntimeException e)
    {
        FAIL() << "Exception thrown:" << e.getReason();
    }
}


TEST_F(AFLForkserverExecutorTest, sharedMemInputDeliv) {
    try {

        //Create executor modules needed for this test
        executor = new AFLForkserverExecutor(ExecModuleNameShmem);
        testHelper->addModule(executor);

        setupExecutorTest();

        //Add a test case to storage (this should not crash)
        char calib[] = "calibrate";
        StorageEntry* entry0 = storage->createNewEntry();
        entry0->allocateAndCopyBuffer(testCaseKey,sizeof(calib),calib);

        //Use this test case to calibrate
        GTEST_COUT << "Calibrating\n";
        std::unique_ptr<Iterator> newEntries = storage->getNewEntries();
        executor->runCalibrationCases(*storage, newEntries);

        char buff_normal[] = "normal";
        StorageEntry* entry1 = storage->createNewEntry();
        entry1->allocateAndCopyBuffer(testCaseKey,sizeof(buff_normal),buff_normal);

        char buff_crash[] = "needle";
        StorageEntry* entry2 = storage->createNewEntry();
        entry2->allocateAndCopyBuffer(testCaseKey,sizeof(buff_crash),buff_crash);

        //Now ask the executor to run the test case
        newEntries->resetIndex();
        executor->runTestCases(*storage, newEntries);

        //Check that it ran normally
        ASSERT_TRUE(entry1->hasTag(normalTag));
        ASSERT_TRUE(entry2->hasTag(crashedTag));
        //Check that they have new coverage
        ASSERT_TRUE(entry1->hasTag(hasNewCoverageTag));
        ASSERT_TRUE(entry2->hasTag(hasNewCoverageTag));

        //Check the output of the instrumentation with AFL_DEBUG on to confirm shmem works
        std::string tmp;
        std::ifstream stderr(OUTPUT_DIR + "/forkserver/stderr", std::ios_base::in);
        bool foundMessage = false;
        while (getline(stderr, tmp))
        {
            if (tmp.find("successfully got fuzzing shared memory", 0) != std::string::npos)
            {
                foundMessage = true;
            }
        }
        ASSERT_TRUE(foundMessage);
    } catch(RuntimeException e) {
        FAIL() << "Exception thrown:" << e.getReason();
    }
}

TEST_F(AFLForkserverExecutorTest, fileInputDeliv) {
    try {
        //Create executor modules needed for this test
        executor = new AFLForkserverExecutor(ExecModuleNameFile);
        testHelper->addModule(executor);

        setupExecutorTest();

        //Add a test case to storage (this should not crash)
        char calib[] = "exit 1";
        StorageEntry* entry0 = storage->createNewEntry();
        entry0->allocateAndCopyBuffer(testCaseKey,sizeof(calib),calib);

        //Use this test case to calibrate
        GTEST_COUT << "Calibrating\n";
        std::unique_ptr<Iterator> newEntries = storage->getNewEntries();
        executor->runCalibrationCases(*storage, newEntries);

        char buff1[] = "abort";
        StorageEntry* entry1 = storage->createNewEntry();
        entry1->allocateAndCopyBuffer(testCaseKey,sizeof(buff1),buff1);
        char buff2[] = "exit 1";
        StorageEntry* entry2 = storage->createNewEntry();
        entry2->allocateAndCopyBuffer(testCaseKey,sizeof(buff2),buff2);

        //Now ask the executor to run the test case
        newEntries->resetIndex();
        GTEST_COUT << "Running test batch #1\n";
        executor->runTestCases(*storage, newEntries);

        //Check that it ran normally
        ASSERT_TRUE(entry1->hasTag(crashedTag));
        ASSERT_TRUE(entry2->hasTag(normalTag));
        //Check that entry1 has new coverage
        ASSERT_TRUE(entry1->hasTag(hasNewCoverageTag));

    } catch(RuntimeException e) {
        FAIL() << "Exception thrown:" << e.getReason();
    }
}

TEST_F(AFLForkserverExecutorTest, debugLog) {
    try {
        //Create executor modules needed for this test
        executor = new AFLForkserverExecutor(ExecModuleNameDebugLog);
        testHelper->addModule(executor);

        setupExecutorTest();

        //Add a test case to storage (this should not crash)
        char calib[] = "exit 1";
        StorageEntry* entry0 = storage->createNewEntry();
        entry0->allocateAndCopyBuffer(testCaseKey,sizeof(calib),calib);

        //Use this test case to calibrate
        GTEST_COUT << "Calibrating\n";
        std::unique_ptr<Iterator> newEntries = storage->getNewEntries();
        executor->runCalibrationCases(*storage, newEntries);

        std::string tmp;
        std::ifstream stdout(OUTPUT_DIR + "/forkserver/stdout", std::ios_base::in);
        getline(stdout, tmp);
        
        bool stdout_match = (tmp.find("<Walks away with a sign displaying", 0) != std::string::npos);
        
        //Check that it ran normally
        ASSERT_TRUE(stdout_match);

    } catch(RuntimeException e) {
        FAIL() << "Exception thrown:" << e.getReason();
    }
}

TEST_F(AFLForkserverExecutorTest, newCoverage) {
    try {
        //Create executor modules needed for this test
        executor = new AFLForkserverExecutor(ExecModuleNameMime);
        testHelper->addModule(executor);
        setupExecutorTest();

        //Add a test case to storage (this should not crash)
        char calib[] = "exit 1";
        StorageEntry* entry0 = storage->createNewEntry();
        entry0->allocateAndCopyBuffer(testCaseKey,sizeof(calib),calib);

        //Use this test case to calibrate
        GTEST_COUT << "Calibrating\n";
        std::unique_ptr<Iterator> newEntries = storage->getNewEntries();
        executor->runCalibrationCases(*storage, newEntries);

        char buff1[] = "coverage 1";
        StorageEntry* entry1 = storage->createNewEntry();
        entry1->allocateAndCopyBuffer(testCaseKey,sizeof(buff1),buff1);
        char buff2[] = "coverage 2";
        StorageEntry* entry2 = storage->createNewEntry();
        entry2->allocateAndCopyBuffer(testCaseKey,sizeof(buff2),buff2);
        char buff3[] = "coverage 3";
        StorageEntry* entry3 = storage->createNewEntry();
        entry3->allocateAndCopyBuffer(testCaseKey,sizeof(buff3),buff3);
        
        // Run test cases through Executor
        newEntries->resetIndex();
        GTEST_COUT << "Running incremental coverage test batch\n";
        executor->runTestCases(*storage, newEntries);

        // Check for increasing coverage
        ASSERT_TRUE(entry1->hasTag(hasNewCoverageTag));
        ASSERT_TRUE(entry2->hasTag(hasNewCoverageTag));
        ASSERT_TRUE(entry3->hasTag(hasNewCoverageTag));

    } catch(RuntimeException e) {
        FAIL() << "Exception thrown:" << e.getReason();
    }
}

TEST_F(AFLForkserverExecutorTest, noNewCoverage) {
    try {
        //Create executor modules needed for this test
        executor = new AFLForkserverExecutor(ExecModuleNameMime);
        testHelper->addModule(executor);
        setupExecutorTest();

        //Add a test case to storage (this should not crash)
        char calib[] = "exit 1";
        StorageEntry* entry0 = storage->createNewEntry();
        entry0->allocateAndCopyBuffer(testCaseKey,sizeof(calib),calib);

        //Use this test case to calibrate
        GTEST_COUT << "Calibrating\n";
        std::unique_ptr<Iterator> newEntries = storage->getNewEntries();
        executor->runCalibrationCases(*storage, newEntries);

        char buff1[] = "coverage 1";
        StorageEntry* entry1 = storage->createNewEntry();
        entry1->allocateAndCopyBuffer(testCaseKey,sizeof(buff1),buff1);
        char buff2[] = "coverage 1";
        StorageEntry* entry2 = storage->createNewEntry();
        entry2->allocateAndCopyBuffer(testCaseKey,sizeof(buff2),buff2);
        char buff3[] = "coverage 1";
        StorageEntry* entry3 = storage->createNewEntry();
        entry3->allocateAndCopyBuffer(testCaseKey,sizeof(buff3),buff3);
        
        // Run test cases through Executor
        newEntries->resetIndex();
        GTEST_COUT << "Running incremental coverage test batch\n";
        executor->runTestCases(*storage, newEntries);

        // Check for increasing coverage
        ASSERT_TRUE(entry1->hasTag(hasNewCoverageTag));
        ASSERT_FALSE(entry2->hasTag(hasNewCoverageTag));
        ASSERT_FALSE(entry3->hasTag(hasNewCoverageTag));

    } catch(RuntimeException e) {
        FAIL() << "Exception thrown:" << e.getReason();
    }
}

TEST_F(AFLForkserverExecutorTest, exitIsCrash) {
    try {
        //Create executor modules needed for this test
        executor = new AFLForkserverExecutor(ExecModuleNameExitIsCrash);
        testHelper->addModule(executor);
        setupExecutorTest();

        //Add a test case to storage (this should not crash)
        char calib[] = "exit 1";
        StorageEntry* entry0 = storage->createNewEntry();
        entry0->allocateAndCopyBuffer(testCaseKey,sizeof(calib),calib);

        //Use this test case to calibrate
        GTEST_COUT << "Calibrating\n";
        std::unique_ptr<Iterator> newEntries = storage->getNewEntries();
        executor->runCalibrationCases(*storage, newEntries);

        char buff1[] = "exit 99";
        StorageEntry* entry1 = storage->createNewEntry();
        entry1->allocateAndCopyBuffer(testCaseKey,sizeof(buff1),buff1);
        
        // Run test cases through Executor
        newEntries->resetIndex();
        GTEST_COUT << "Running incremental coverage test batch\n";
        executor->runTestCases(*storage, newEntries);

        // Check for increasing coverage
        ASSERT_TRUE(entry1->hasTag(crashedTag));

    } catch(RuntimeException e) {
        FAIL() << "Exception thrown:" << e.getReason();
    }
}


TEST_F(AFLForkserverExecutorTest, multiCrash) {
    try {
        //Create executor modules needed for this test
        executor = new AFLForkserverExecutor(ExecModuleNameMime);
        testHelper->addModule(executor);
        setupExecutorTest();

        //Add a test case to storage (this should not crash)
        char calib[] = "exit 1";
        StorageEntry* entry0 = storage->createNewEntry();
        entry0->allocateAndCopyBuffer(testCaseKey,sizeof(calib),calib);

        //Use this test case to calibrate
        GTEST_COUT << "Calibrating\n";
        std::unique_ptr<Iterator> newEntries = storage->getNewEntries();
        executor->runCalibrationCases(*storage, newEntries);

        char buff1[] = "abort";
        StorageEntry* entry1 = storage->createNewEntry();
        entry1->allocateAndCopyBuffer(testCaseKey,sizeof(buff1),buff1);
        char buff2[] = "segv";
        StorageEntry* entry2 = storage->createNewEntry();
        entry2->allocateAndCopyBuffer(testCaseKey,sizeof(buff2),buff2);
        char buff3[] = "term";
        StorageEntry* entry3 = storage->createNewEntry();
        entry3->allocateAndCopyBuffer(testCaseKey,sizeof(buff3),buff3);
        char buff4[] = "exit 1";
        StorageEntry* entry4 = storage->createNewEntry();
        entry4->allocateAndCopyBuffer(testCaseKey,sizeof(buff4),buff4);
        
        // Run test cases through Executor
        newEntries->resetIndex();
        GTEST_COUT << "Running incremental coverage test batch\n";
        executor->runTestCases(*storage, newEntries);

        // Check for increasing coverage
        ASSERT_TRUE(entry1->hasTag(crashedTag));
        ASSERT_TRUE(entry2->hasTag(crashedTag));
        ASSERT_TRUE(entry3->hasTag(crashedTag));
        ASSERT_TRUE(entry4->hasTag(normalTag));

    } catch(RuntimeException e) {
        FAIL() << "Exception thrown:" << e.getReason();
    }
}

TEST_F(AFLForkserverExecutorTest, multiHang) {
    try {
        //Create executor modules needed for this test
        executor = new AFLForkserverExecutor(ExecModuleNameMime);
        testHelper->addModule(executor);
        setupExecutorTest();

        //Add a test case to storage (this should not crash)
        char calib[] = "exit 1";
        StorageEntry* entry0 = storage->createNewEntry();
        entry0->allocateAndCopyBuffer(testCaseKey,sizeof(calib),calib);

        //Use this test case to calibrate
        GTEST_COUT << "Calibrating\n";
        std::unique_ptr<Iterator> newEntries = storage->getNewEntries();
        executor->runCalibrationCases(*storage, newEntries);

        char buff1[] = "hang";
        StorageEntry* entry1 = storage->createNewEntry();
        entry1->allocateAndCopyBuffer(testCaseKey,sizeof(buff1),buff1);
        char buff2[] = "hang";
        StorageEntry* entry2 = storage->createNewEntry();
        entry2->allocateAndCopyBuffer(testCaseKey,sizeof(buff2),buff2);
        char buff3[] = "hang";
        StorageEntry* entry3 = storage->createNewEntry();
        entry3->allocateAndCopyBuffer(testCaseKey,sizeof(buff3),buff3);
        char buff4[] = "exit 1";
        StorageEntry* entry4 = storage->createNewEntry();
        entry4->allocateAndCopyBuffer(testCaseKey,sizeof(buff4),buff4);
        
        // Run test cases through Executor
        newEntries->resetIndex();
        GTEST_COUT << "Running incremental coverage test batch\n";
        executor->runTestCases(*storage, newEntries);

        // Check for increasing coverage
        ASSERT_TRUE(entry1->hasTag(hungTag));
        ASSERT_TRUE(entry2->hasTag(hungTag));
        ASSERT_TRUE(entry3->hasTag(hungTag));
        ASSERT_TRUE(entry4->hasTag(normalTag));

    } catch(RuntimeException e) {
        FAIL() << "Exception thrown:" << e.getReason();
    }
}

TEST_F(AFLForkserverExecutorTest, asanCrash) {
    try {
        //Create executor modules needed for this test
        executor = new AFLForkserverExecutor(ExecModuleNameAsan);
        testHelper->addModule(executor);
        setupExecutorTest();

        //Add a test case to storage (this should not crash)
        char calib[] = "exit 1";
        StorageEntry* entry0 = storage->createNewEntry();
        entry0->allocateAndCopyBuffer(testCaseKey,sizeof(calib),calib);

        //Use this test case to calibrate
        GTEST_COUT << "Calibrating\n";
        std::unique_ptr<Iterator> newEntries = storage->getNewEntries();
        executor->runCalibrationCases(*storage, newEntries);

        char buff1[] = "asan";
        StorageEntry* entry1 = storage->createNewEntry();
        entry1->allocateAndCopyBuffer(testCaseKey,sizeof(buff1),buff1);
        
        // Run test cases through Executor
        newEntries->resetIndex();
        GTEST_COUT << "Running incremental coverage test batch\n";
        executor->runTestCases(*storage, newEntries);

        // Check for increasing coverage
        ASSERT_TRUE(entry1->hasTag(crashedTag));

    } catch(RuntimeException e) {
        FAIL() << "Exception thrown:" << e.getReason();
    }
}

TEST_F(AFLForkserverExecutorTest, legacyInstr) {
    try {
        //Create executor modules needed for this test
        executor = new AFLForkserverExecutor(ExecModuleNameLegacy);
        testHelper->addModule(executor);
        setupExecutorTest();

        //Add a test case to storage (this should not crash)
        char calib[] = "exit 1";
        StorageEntry* entry0 = storage->createNewEntry();
        entry0->allocateAndCopyBuffer(testCaseKey,sizeof(calib),calib);

        //Use this test case to calibrate
        GTEST_COUT << "Calibrating\n";
        std::unique_ptr<Iterator> newEntries = storage->getNewEntries();
        executor->runCalibrationCases(*storage, newEntries);

        char buff1[] = "exit 1";
        StorageEntry* entry1 = storage->createNewEntry();
        entry1->allocateAndCopyBuffer(testCaseKey,sizeof(buff1),buff1);
        char buff2[] = "hang";
        StorageEntry* entry2 = storage->createNewEntry();
        entry2->allocateAndCopyBuffer(testCaseKey,sizeof(buff2),buff2);
        char buff3[] = "hang";
        StorageEntry* entry3 = storage->createNewEntry();
        entry3->allocateAndCopyBuffer(testCaseKey,sizeof(buff3),buff3);
        char buff4[] = "abort";
        StorageEntry* entry4 = storage->createNewEntry();
        entry4->allocateAndCopyBuffer(testCaseKey,sizeof(buff4),buff4);
        char buff5[] = "segv";
        StorageEntry* entry5 = storage->createNewEntry();
        entry5->allocateAndCopyBuffer(testCaseKey,sizeof(buff5),buff5);
        char buff6[] = "exit 1";
        StorageEntry* entry6 = storage->createNewEntry();
        entry6->allocateAndCopyBuffer(testCaseKey,sizeof(buff6),buff6);
        
        // Run test cases through Executor
        newEntries->resetIndex();
        GTEST_COUT << "Running incremental coverage test batch\n";
        executor->runTestCases(*storage, newEntries);

        // Check for increasing coverage
        ASSERT_TRUE(entry1->hasTag(normalTag));
        ASSERT_TRUE(entry2->hasTag(hungTag));
        ASSERT_TRUE(entry3->hasTag(hungTag));
        ASSERT_TRUE(entry4->hasTag(crashedTag));
        ASSERT_TRUE(entry5->hasTag(crashedTag));
        ASSERT_TRUE(entry6->hasTag(normalTag));

    } catch(RuntimeException e) {
        FAIL() << "Exception thrown:" << e.getReason();
    }
}

