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
#include <filesystem>
#include <iostream>
#include <string>

#include "gtest/gtest.h"
#include "SaveCorpusOutput.hpp"
#include "ModuleTestHelper.hpp"
#include "StorageModuleStructures.hpp"

using namespace vmf;
namespace fs = std::filesystem;

#define GTEST_COUT std::cerr << "[          ] [ INFO ]"



class SaveCorpusOutputTest : public ::testing::Test {
protected:


    SaveCorpusOutputTest()
    {
        //This provides basic VMF logging, which is useful for debugging storage registration errors
        Logging::initConsoleLog();
    }

    void SetUp() override {
        testHelper = new ModuleTestHelper();
        SaveCorpusOutput = new vmf::SaveCorpusOutput(SCOModuleName);
        testHelper->addModule(SaveCorpusOutput);

        config = testHelper->getConfig();
        storage = testHelper->getStorage();

        fs::path outputDir = "./unittest_output/SaveCorpusOutput";
        config->setOutputDir(outputDir.string());
        fs::create_directories(outputDir);
    }

    void TearDown() override {
        delete testHelper;
        //The ModuleTestHelper destructor will also delete any added modules
    }

    //Module specific test setup
    void configure()
    {
        config->setBoolParam(SCOModuleName, "recordTestMetadata", true);

        //Register for relevant storage handles that we need to read or write within the unit test
        //(the module's registerStorageNeeds method is called automatically by the ModuleTestHelper)
        StorageRegistry* registry = testHelper->getRegistry();
        normalTag = registry->registerTag("RAN_SUCCESSFULLY", StorageRegistry::WRITE_ONLY);
        crashedTag = registry->registerTag("CRASHED", StorageRegistry::WRITE_ONLY);
        hungTag = registry->registerTag("HUNG", StorageRegistry::WRITE_ONLY);
    
        testCaseKey = registry->registerKey("TEST_CASE", StorageRegistry::BUFFER, StorageRegistry::READ_WRITE);
        mutatorIdKey = registry->registerKey("MUTATOR_ID", StorageRegistry::INT, StorageRegistry::WRITE_ONLY);
        testcaseParentIdKey = registry->registerKey("PARENT_ID", StorageRegistry::UINT, StorageRegistry::WRITE_ONLY);
        generationKey = registry->registerKey("GENERATION", StorageRegistry::UINT, StorageRegistry::WRITE_ONLY);
        numChildrenKey = registry->registerKey("NUM_CHILDREN", StorageRegistry::UINT, StorageRegistry::WRITE_ONLY);
        execTimeKey = registry->registerKey("EXEC_TIME_US", StorageRegistry::UINT, StorageRegistry::WRITE_ONLY);
        execTimestampKey = registry->registerKey("EXEC_TIMESTAMP_US", StorageRegistry::UINT, StorageRegistry::WRITE_ONLY);
        
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

    
    ModuleTestHelper* testHelper; //testHelper will destroy all of the modules when it is destroyed
    OutputModule* SaveCorpusOutput;
    TestConfigInterface* config;
    StorageModule* storage;
    std::string SCOModuleName = "SaveCorpusOutput";

    //Storage fields that are read or written by this unit test
    int normalTag;
    int crashedTag;
    int hungTag;
    int testCaseKey;
    int testcaseParentIdKey;
    int generationKey;
    int numChildrenKey;
    int mutatorIdKey;
    int execTimeKey;
    int execTimestampKey;
};

/* Custom assertion that:
- For all testcases in the corpus, there is a metadat file containing the configured metadata information
*/
void validateMetadata(TestConfigInterface* config, const std::vector<Testcase> &testcases)
{
    bool outputMetadata = false;
    YAML::Node metadata;
    for (const auto& entry : fs::recursive_directory_iterator(config->getOutputDir())) 
    {
        // Get the full path of the current entry.
        const auto& entry_path = entry.path();

        // Check if the entry is a regular file.
        if (entry.is_regular_file() && 
            entry_path.filename().string().rfind("_metadata") != std::string::npos) {
            outputMetadata = true;
            int testcaseId = stoi(entry_path.filename().string().substr(0, 1)); // expecting single digit testcase IDs
            metadata = YAML::LoadFile(entry_path.string());
            Testcase expected_metadata = testcases[testcaseId - 1];
            GTEST_COUT << "Parent is: " << metadata["parent"] << std::endl;
            GTEST_COUT << "Generation is: " << metadata["generation"] << std::endl;
            GTEST_COUT << "mutator is: " << metadata["mutator"] << std::endl;
            ASSERT_GE(metadata["parent"].as<uint64_t>(), expected_metadata.parentId);
            ASSERT_GE(metadata["generation"].as<uint64_t>(), expected_metadata.generation);
            ASSERT_STREQ(metadata["mutator"].as<std::string>().c_str(), expected_metadata.mutatorId == -1? 
                "<NULL>" : "Method not implemented");
                // TODO: "Method not implemented" comes from TestConfigInterface::getModuleName, update once 
                // this method is implemented
        }
    }

    ASSERT_TRUE(outputMetadata) << "No metadata files were output";

    // EXPECT_THAT(parents, testing::Contains(target_number));

}

/* Verify that SCO can output a basic corpus */
TEST_F(SaveCorpusOutputTest, nominal)
{
    configure();

    // Add some basic testcases to the corpus with associated metadata
    std::vector<Testcase> testcases; testcases.resize(2);
    testcases[0].buff = "VMF";
    testcases[0].parentId = 0;
    testcases[0].generation = 0;
    testcases[0].mutatorId = -1;

    // test case ID 2
    testcases[1].buff = "TEST";
    testcases[1].parentId = 1;
    testcases[1].generation = 0;
    testcases[1].mutatorId = 1;

    for (auto testcase : testcases)
    {
        //Add some seed test cases to storage
        //These all need to be saved and marked with the normal tag in order to be used
        std::vector<char> writable_copy(testcase.buff.begin(), testcase.buff.end());
        writable_copy.push_back('\0'); // Add the null terminator

        char* writable_ptr = writable_copy.data();
        StorageEntry* entry1 = storage->createNewEntry();
        entry1->allocateAndCopyBuffer(testCaseKey,testcase.buff.length(),writable_ptr);
        entry1->setValue(testcaseParentIdKey, testcase.parentId);
        entry1->setValue(generationKey, testcase.generation);
        entry1->setValue(mutatorIdKey, testcase.mutatorId);
        storage->saveEntry(entry1);
    }

    // Execute output of corpus
    SaveCorpusOutput->run(*storage);

    // Verify correctness of the output metadata
    validateMetadata(config, testcases);
}
