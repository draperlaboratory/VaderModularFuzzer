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
#include <filesystem>
#include <regex>
#include "gtest/gtest.h"
#include "IterativeController.hpp"
#include "SimpleStorage.hpp"
#include "RuntimeException.hpp"
#include "ModuleTestHelper.hpp"
#include "KleeInitialization.hpp"
#include "TestConfigInterface.hpp"
#include "VmfUtil.hpp"

using namespace vmf;
namespace fs = std::filesystem;

#define GTEST_COUT std::cerr << "[          ] [ INFO ]"

std::string get_klee_path() {
    std::array<char, 128> buffer;
    std::string path;
    std::string cmd = "which klee";
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd.c_str(), "r"), pclose);

    if (!pipe) {
        throw std::runtime_error("Failed to determine klee installation location");
    }

    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr)
    {
        path += buffer.data();
    }

    if (!path.empty() && path.back() == '\n')
    {
        path.pop_back();
    }

    return path;
}


bool file_contains_substring(const fs::path& filePath, const std::string& substring) {
    std::ifstream file(filePath);
    if (!file.is_open()) {
        return false;
    }

    std::string line;
    while (std::getline(file, line)) {
        if (line.find(substring) != std::string::npos) {
            return true;
        }
    }

    return false;
}

class KleeInitializationTest : public ::testing::Test {
protected:
    KleeInitializationTest()
    {
        //This provides basic VMF logging, which is useful for debugging storage registration errors
        Logging::initConsoleLog();
    }

    void SetUp() override {
        testHelper = new ModuleTestHelper();
        config = testHelper->getConfig();
        storage = testHelper->getStorage();

        // create output directory freshly for each test case
        VmfUtil::createDirectory(OUTPUT_DIR.c_str());
    }

    void TearDown() override {
        // remove output dir at tear down to run each test with fresh output dir
        if (fs::exists(OUTPUT_DIR)) {
            // fs::remove_all(OUTPUT_DIR);
        }
        //The ModuleTestHelper destructor will also delete any added modules
            delete testHelper;
    }

    //Module specific test setup
    void setupExecutorTest(std::string bcFilePath)
    {
        setup_configuration(bcFilePath);

        configure_storage();

        //Initialize everything using the ModuleTestHelper class
        testHelper->initializeModulesAndStorage();
    }

    void configure_storage()
    {
        // Register for relevant storage handles that we need to read or write within the unit test
        //(the module's registerStorageNeeds method is called automatically by the ModuleTestHelper)
        StorageRegistry *registry = testHelper->getRegistry();
        testCaseKey = registry->registerKey("TEST_CASE", StorageRegistry::BUFFER, StorageRegistry::WRITE_ONLY);
        execTimeKey = registry->registerKey("EXEC_TIME_US", StorageRegistry::UINT, StorageRegistry::WRITE_ONLY);
    }

    void setup_configuration(std::string bcFilePath)
    {
        // This module requires the output directory parameter
        config->setOutputDir(OUTPUT_DIR);

        // Core dump check is disabled so this test can run on CI/CD
        config->setBoolParam(ExecModuleName, "enableCoreDumpCheck", false);
    }

    // relative to vader/build directory
    std::string OUTPUT_DIR = "./unittestKleeInit_output/";
    
    ModuleTestHelper* testHelper; //testHelper will destroy all of the modules when it is destroyed
    ExecutorModule* executor;
    TestConfigInterface* config;
    StorageModule* storage;
    std::string ExecModuleName = "KleeInitialization";

    std::string haystack_bc = "test/unittest/inputs/KleeInitializer/haystack.bc";

    //Storage fields that are read or written by this unit test
    int normalTag;
    int crashedTag;
    int hungTag;
    int hasNewCoverageTag;
    int testCaseKey;
    int execTimeKey;
};


TEST_F(KleeInitializationTest, nominal)
{
    KleeInitialization* initModule = new KleeInitialization(ExecModuleName);
    testHelper->addModule(initModule);
    config->setStringParam(ExecModuleName, "bitcodeFilePath", haystack_bc);
    config->setStringVectorParam(ExecModuleName,"sutArgv", {haystack_bc});

    // relative to vader/build
    setupExecutorTest(haystack_bc);

    std::string gen_test_case_dir = OUTPUT_DIR+"/klee_gen_testcases";
    std::string klee_working_dir = OUTPUT_DIR+"/klee_working_dir";
    ASSERT_TRUE(fs::exists(gen_test_case_dir)) << " Failed to generate klee_gen_testcases";
    ASSERT_TRUE(fs::exists(klee_working_dir)) << " Failed to generate klee_working_dir";

    initModule->run(*storage);

    std::string klee_output_dir = klee_working_dir+"/klee-last";
    ASSERT_TRUE(fs::exists(klee_output_dir)) << " Failed to generate klee_working_dir/klee-last";

    std::regex testCasePattern(R"(input\d+)");
    std::regex kleeOutputPattern(R"(.*ktest)");
    std::string substring = "needle";
    bool found = false;
    int num_testcases = 0;
    int num_kleeOutputs = 0;

    // check for klee outputs
    for (const auto& entry: fs::directory_iterator(klee_output_dir)) {
        if (fs::is_regular_file(entry) && std::regex_match(entry.path().filename().string(), kleeOutputPattern)) {
            num_kleeOutputs++;
        }
    }

    ASSERT_GT(num_kleeOutputs, 0) << " Failed to produce any klee output";

    // check for generated test cases from klee outputs
    for (const auto& entry: fs::directory_iterator(gen_test_case_dir)) {
        if (fs::is_regular_file(entry) && std::regex_match(entry.path().filename().string(), testCasePattern)) {
            num_testcases++;
            if (file_contains_substring(entry.path(), substring)) {
                found = true;
            }
        }
    }

    ASSERT_TRUE(found) << " Failed to solve for needle input";
    ASSERT_GT(num_testcases, 0) << " Failed to produce any testcases from klee output";

    int num_testcases_in_storage = 0;
    std::unique_ptr<Iterator> testcaseIter = storage->getNewEntries();
    StorageEntry* e = nullptr;
    while(testcaseIter->hasNext())
    {
        e = testcaseIter->getNext();
        num_testcases_in_storage++;
    }

    ASSERT_EQ(num_testcases_in_storage, num_testcases) << " Failed to absorb all test cases into storage";
}


TEST_F(KleeInitializationTest, inputValidationMissingSut)
{
    try {
        Module* initModule = new KleeInitialization(ExecModuleName);
        testHelper->addModule(initModule);
        config->setStringParam(ExecModuleName, "bitcodeFilePath", "test/unittest/inputs/KleeInitializer/missing_haystack.bc");
        config->setStringVectorParam(ExecModuleName,"sutArgv", {"test/unittest/inputs/KleeInitializer/missing_haystack.bc"});

        // relative to vader/build
        setupExecutorTest(haystack_bc);

        FAIL() << " Incorrectly initialized against a missing SUT";
    } catch (RuntimeException e) {
        ASSERT_STREQ(e.getReason().c_str(), "Specified .bc file not found");
        ASSERT_EQ(e.getErrorCode(), RuntimeException::CONFIGURATION_ERROR);
    } catch (...) {
        FAIL() << " Threw unexpected exception";
    }
}


TEST_F(KleeInitializationTest, inputValidationInvalidSut)
{   
    std::string invalid_sut_path = "test/unittest/inputs/KleeInitializer/haystack.invalid";
    try {
        Module* initModule = new KleeInitialization(ExecModuleName);
        testHelper->addModule(initModule);
        if (!fs::exists(invalid_sut_path))
            fs::copy(haystack_bc, invalid_sut_path);
        config->setStringParam(ExecModuleName, "bitcodeFilePath", invalid_sut_path);
        config->setStringVectorParam(ExecModuleName,"sutArgv", {invalid_sut_path});

        // relative to vader/build
        setupExecutorTest(haystack_bc);

        FAIL() << " Incorrectly initialized against a missing SUT";
    } catch (RuntimeException e) {
        ASSERT_STREQ(e.getReason().c_str(), "Klee Initialization input not in expected format");
        ASSERT_EQ(e.getErrorCode(), RuntimeException::CONFIGURATION_ERROR);
    } catch (...) {
        FAIL() << " Threw unexpected exception";
    }
}


TEST_F(KleeInitializationTest, inputValidationMissingOutputDirectory)
{
    try {
        Module* initModule = new KleeInitialization(ExecModuleName);
        testHelper->addModule(initModule);
        config->setStringParam(ExecModuleName, "bitcodeFilePath", haystack_bc);
        config->setStringVectorParam(ExecModuleName,"sutArgv", {haystack_bc});

        fs::remove_all(OUTPUT_DIR);

        // relative to vader/build
        setupExecutorTest(haystack_bc);

        FAIL() << " Incorrectly initialized against a missing output directory";
    } catch (RuntimeException e) {
        ASSERT_STREQ(e.getReason().c_str(), "Missing output directory");
        ASSERT_EQ(e.getErrorCode(), RuntimeException::OTHER);
    } catch (...) {
        FAIL() << " Threw unexpected exception";
    }
}
