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
#include "GeneticAlgorithmInputGenerator.hpp"
#include "RuntimeException.hpp"
#include "ModuleTestHelper.hpp"
#include "StorageRegistry.hpp"
#include "StorageEntry.hpp"
#include "SimpleStorage.hpp"
#include "StorageEntry.hpp"
#include "DictionaryMutator.hpp"

#include <filesystem>

using namespace vmf;

#define GTEST_COUT std::cerr << "[          ] [ INFO ]"


TEST(DictionaryMutatorTest, missingConfigPath){
    std::filesystem::remove_all(std::filesystem::path("strings.dict"));
    Module* dm = new DictionaryMutator("DictionaryMutator");
    TestConfigInterface config;
    config.addSubmodule("DictionaryMutator", dm);
    dm->init(config);

    delete dm;
}


TEST(DictionaryMutatorTest, missingConfigPathIntegrated)
{
    // Copy over default strings dict to hard-coded default dictionary location
    std::filesystem::remove_all(std::filesystem::path("strings.dict"));
    ModuleTestHelper testHelper = ModuleTestHelper();

    //Add mutators to testHelper
    DictionaryMutator* mutator = new DictionaryMutator("DictionaryMutator");
    testHelper.addModule(mutator);

    TestConfigInterface* config = testHelper.getConfig();

    //Setup config data
    config->addSubmodule("DictionaryMutator", mutator);
    testHelper.initializeModulesAndStorage();
}

// Test of mutation with neither a default dict or user specified dict present
TEST(DictionaryMutatorTest, noInputIntegrated)
{
    ModuleTestHelper testHelper =  ModuleTestHelper();

    // Remove hard-coded `strings.dict` if present
    std::filesystem::remove_all(std::filesystem::path("strings.dict"));

    //Add mutators to testHelper
    MutatorModule* mutator = new DictionaryMutator("DictionaryMutator");
    testHelper.addModule(mutator);

    // Register tags
    StorageRegistry* registry = testHelper.getRegistry();
    int testCaseKey = registry->registerKey("TEST_CASE", StorageRegistry::BUFFER, StorageRegistry::READ_WRITE);

    //Setup config data
    TestConfigInterface* config = testHelper.getConfig();
    config->addSubmodule("DictionaryMutator", mutator);
    testHelper.initializeModulesAndStorage();

    // Add a test case and mutate it
    StorageModule* storage = testHelper.getStorage();
    char buff1[] = {'V','M','F', '\n'};
    StorageEntry* base_entry = storage->createNewEntry();
    base_entry->allocateAndCopyBuffer(testCaseKey,3,buff1);
    storage->saveEntry(base_entry);

    StorageEntry* mod_entry = storage->createNewEntry();

    try{
        mutator->mutateTestCase(*storage, base_entry, mod_entry, testCaseKey);
        FAIL() << "failed to throw expected error";
    } catch (RuntimeException e) {
        EXPECT_EQ( e.getErrorCode(), RuntimeException::USAGE_ERROR);
        EXPECT_STREQ( e.getReason().c_str(), "Blank token list");
    } catch (...) {
        FAIL() << "Threw unexpected error";
    }
}

// Test of mutation without a default dict present but a user provided blank dictionary
TEST(DictionaryMutatorTest, blankInputIntegrated)
{
    try {
        ModuleTestHelper testHelper =  ModuleTestHelper();

        // Remove hard-coded `strings.dict` if present
        std::filesystem::remove_all(std::filesystem::path("strings.dict"));

        //Add mutators to testHelper
        MutatorModule* mutator = new DictionaryMutator("DictionaryMutator");
        testHelper.addModule(mutator);

        // Register tags
        StorageRegistry* registry = testHelper.getRegistry();
        int testCaseKey = registry->registerKey("TEST_CASE", StorageRegistry::BUFFER, StorageRegistry::READ_WRITE);

        //Setup config data
        TestConfigInterface* config = testHelper.getConfig();
        config->setStringVectorParam("DictionaryMutator", "dictionaryPaths", {"../test/unittest/inputs/DictionaryMutator/strings-blank.txt"});
        config->addSubmodule("DictionaryMutator", mutator);
        testHelper.initializeModulesAndStorage();

        // Add a test case and mutate it
        StorageModule* storage = testHelper.getStorage();
        char buff1[] = {'V','M','F', '\n'};
        StorageEntry* base_entry = storage->createNewEntry();
        base_entry->allocateAndCopyBuffer(testCaseKey,3,buff1);
        storage->saveEntry(base_entry);

        StorageEntry* mod_entry = storage->createNewEntry();

        mutator->mutateTestCase(*storage, base_entry, mod_entry, testCaseKey);

        // Fail if this did not throw an exception
        FAIL() << "Failed to throw expected exception";
    } catch (RuntimeException e) {
        EXPECT_EQ( e.getErrorCode(), RuntimeException::USAGE_ERROR);
        EXPECT_STREQ( e.getReason().c_str(), "Blank token list");
    } catch (...) {
        FAIL() << "Expected RuntimeException(\"Blank token list\", RuntimeException::USAGE_ERROR)";
    }
}


// Test of mutation with a default dict present but no user provided dictionary
TEST(DictionaryMutatorTest, defaultInputIntegrated)
{
    ModuleTestHelper testHelper =  ModuleTestHelper();

    // Copy over default strings dict to hard-coded default dictionary location
    std::filesystem::copy(
        std::filesystem::path("../test/unittest/inputs/DictionaryMutator/strings.txt"),
        std::filesystem::path("strings.dict")
    );

    //Add mutators to testHelper
    MutatorModule* mutator = new DictionaryMutator("DictionaryMutator");
    testHelper.addModule(mutator);

    // Register tags
    StorageRegistry* registry = testHelper.getRegistry();
    int testCaseKey = registry->registerKey("TEST_CASE", StorageRegistry::BUFFER, StorageRegistry::READ_WRITE);

    //Setup config data
    TestConfigInterface* config = testHelper.getConfig();
    config->setOutputDir("./");
    config->setStringVectorParam("DictionaryMutator", "dictionaryPaths", {"../test/unittest/inputs/DictionaryMutator/strings-blank.txt"});
    config->addSubmodule("DictionaryMutator", mutator);
    testHelper.initializeModulesAndStorage();

    // Add a test case and mutate it
    StorageModule* storage = testHelper.getStorage();
    char buff1[] = {'V','M','F', '\n'};
    StorageEntry* base_entry = storage->createNewEntry();
    base_entry->allocateAndCopyBuffer(testCaseKey,3,buff1);
    storage->saveEntry(base_entry);

    StorageEntry* mod_entry = storage->createNewEntry();

    try
    {
        mutator->mutateTestCase(*storage, base_entry, mod_entry, testCaseKey);
    }
    catch (BaseException e)
    {
        FAIL() << "Exception when mutating: " << e.getReason();
    }

    // assert that all test cases contain the token in the list of tokens
    std::string token = "/lib64/ld-linux-x86-64.so.2";
    StorageEntry* e;
    bool contains_correctly_mutated_testcase = false;
    int contains_correctly_mutated_testcase_count = 0;

    std::unique_ptr<Iterator> testcaseIter = storage->getNewEntries();
    while(testcaseIter->hasNext())
    {
        e = testcaseIter->getNext();
        std::string _buff = e->getBufferPointer(testCaseKey);
        GTEST_COUT << " testcase: " << _buff << std::endl;
        if (_buff.find(token) != std::string::npos) {
            contains_correctly_mutated_testcase |= true;
            contains_correctly_mutated_testcase_count += 1;
        }
    }
    ASSERT_TRUE(contains_correctly_mutated_testcase) << "Could not find " << token << " in any  test case";
    ASSERT_TRUE(contains_correctly_mutated_testcase_count == 1)  << "Not all testcases were mutated with token: " << token << " (Num test cases mutated: "<< contains_correctly_mutated_testcase_count <<")";

}


// Test of mutation without a default dict present but a user provided non-blank dictionary
TEST(DictionaryMutatorTest, noDefaultInputIntegrated)
{
    ModuleTestHelper testHelper =  ModuleTestHelper();

    // Remove hard-coded `strings.dict` if present
    std::filesystem::remove_all(std::filesystem::path("strings.dict"));

    //Add mutators to testHelper
    MutatorModule* mutator = new DictionaryMutator("DictionaryMutator");
    testHelper.addModule(mutator);

    // Register tags
    StorageRegistry* registry = testHelper.getRegistry();
    int testCaseKey = registry->registerKey("TEST_CASE", StorageRegistry::BUFFER, StorageRegistry::READ_WRITE);

    //Setup config data
    TestConfigInterface* config = testHelper.getConfig();
    config->setStringVectorParam("DictionaryMutator", "dictionaryPaths", {"../test/unittest/inputs/DictionaryMutator/strings.txt"});
    config->addSubmodule("DictionaryMutator", mutator);
    testHelper.initializeModulesAndStorage();

    // Add a test case and mutate it
    StorageModule* storage = testHelper.getStorage();
    char buff1[] = {'V','M','F', '\n'};
    StorageEntry* base_entry = storage->createNewEntry();
    base_entry->allocateAndCopyBuffer(testCaseKey,3,buff1);
    storage->saveEntry(base_entry);

    StorageEntry* mod_entry = storage->createNewEntry();

    mutator->mutateTestCase(*storage, base_entry, mod_entry, testCaseKey);

    // assert that all test cases contain the token in the list of tokens
    std::string token = "/lib64/ld-linux-x86-64.so.2";
    StorageEntry* e;
    bool contains_correctly_mutated_testcase = false;
    int contains_correctly_mutated_testcase_count = 0;

    std::unique_ptr<Iterator> testcaseIter = storage->getNewEntries();
    while(testcaseIter->hasNext())
    {
        e = testcaseIter->getNext();
        std::string _buff = e->getBufferPointer(testCaseKey);
        GTEST_COUT << " testcase: " << _buff << std::endl;
        if (_buff.find(token) != std::string::npos) {
            contains_correctly_mutated_testcase |= true;
            contains_correctly_mutated_testcase_count += 1;
        }
    }
    ASSERT_TRUE(contains_correctly_mutated_testcase) << "Could not find " << token << " in any  test case";
    ASSERT_TRUE(contains_correctly_mutated_testcase_count == 1)  << "Not all testcases were mutated with token: " << token << " (Num test cases mutated: "<< contains_correctly_mutated_testcase_count <<")";

}


// Test of mutation without a misconfigured user provided dictionary (missing opening quote)
TEST(DictionaryMutatorTest, misconfiguredInputBeginingDoubleQuoteIntegrated)
{
    try {
        ModuleTestHelper testHelper = ModuleTestHelper();

        //Add mutators to testHelper
        MutatorModule* mutator = new DictionaryMutator("DictionaryMutator");
        testHelper.addModule(mutator);

        TestConfigInterface* config = testHelper.getConfig();

        // Register tags
        StorageRegistry* registry = testHelper.getRegistry();
        int testCaseKey = registry->registerKey("TEST_CASE", StorageRegistry::BUFFER, StorageRegistry::READ_WRITE);

        //Setup config data
        config->setStringVectorParam("DictionaryMutator", "dictionaryPaths", {"../test/unittest/inputs/DictionaryMutator/strings-misconfigured-beginning-double-quote.txt"});
        config->addSubmodule("DictionaryMutator", mutator);
        testHelper.initializeModulesAndStorage();

        // Add a test case and mutate it
        StorageModule* storage = testHelper.getStorage();
        char buff1[] = {'V','M','F', '\n'};
        StorageEntry* base_entry = storage->createNewEntry();
        base_entry->allocateAndCopyBuffer(testCaseKey,3,buff1);
        storage->saveEntry(base_entry);

        StorageEntry* mod_entry = storage->createNewEntry();

        mutator->mutateTestCase(*storage, base_entry, mod_entry, testCaseKey);

        FAIL() << "Failed to throw expected exception";
    } catch (RuntimeException e) {
        EXPECT_EQ( e.getErrorCode(), RuntimeException::USAGE_ERROR);
        EXPECT_STREQ( e.getReason().c_str(), "Misformated token line missing opening double quote");
    } catch (...) {
        FAIL() << "Expected RuntimeException(\"Failed to open strings file\", RuntimeException::USAGE_ERROR)";
    }
}


// Test of mutation without a misconfigured user provided dictionary (missing opening quote)
TEST(DictionaryMutatorTest, misconfiguredInputEndingDoubleQuoteIntegrated)
{
    try {
        ModuleTestHelper testHelper =  ModuleTestHelper();

        //Add mutators to testHelper
        MutatorModule* mutator = new DictionaryMutator("DictionaryMutator");
        testHelper.addModule(mutator);

        TestConfigInterface* config = testHelper.getConfig();

        // Register tags
        StorageRegistry* registry = testHelper.getRegistry();
        int testCaseKey = registry->registerKey("TEST_CASE", StorageRegistry::BUFFER, StorageRegistry::READ_WRITE);

        //Setup config data
        config->setStringVectorParam("DictionaryMutator", "dictionaryPaths", {"../test/unittest/inputs/DictionaryMutator/strings-misconfigured-ending-double-quote.txt"});
        config->addSubmodule("DictionaryMutator", mutator);
        testHelper.initializeModulesAndStorage();

        // Add a test case and mutate it
        StorageModule* storage = testHelper.getStorage();
        char buff1[] = {'V','M','F', '\n'};
        StorageEntry* base_entry = storage->createNewEntry();
        base_entry->allocateAndCopyBuffer(testCaseKey,3,buff1);
        storage->saveEntry(base_entry);

        StorageEntry* mod_entry = storage->createNewEntry();

        mutator->mutateTestCase(*storage, base_entry, mod_entry, testCaseKey);

        FAIL() << "Failed to throw expected exception";
    } catch (RuntimeException e) {
        EXPECT_EQ( e.getErrorCode(), RuntimeException::USAGE_ERROR);
        EXPECT_STREQ( e.getReason().c_str(), "Misformated token line missing closing double quote");
    } catch (...) {
        FAIL() << "Expected RuntimeException(\"Failed to open strings file\", RuntimeException::USAGE_ERROR)";
    }
}


// Test of mutation of multiple test cases
TEST(DictionaryMutatorTest, correctlyConfiguredInputIntegrated)
{
    ModuleTestHelper testHelper = ModuleTestHelper();

    //Add mutators to testHelper
    MutatorModule* mutator = new DictionaryMutator("DictionaryMutator");
    testHelper.addModule(mutator);

    //Setup config data
    TestConfigInterface* config = testHelper.getConfig();
    std::string strings_path = "../test/unittest/inputs/DictionaryMutator/strings.txt";
    config->setStringVectorParam("DictionaryMutator", "dictionaryPaths", {strings_path});
    config->addSubmodule("DictionaryMutator", mutator);

    StorageRegistry* registry = testHelper.getRegistry();
    int testCaseKey = registry->registerKey("TEST_CASE", StorageRegistry::BUFFER, StorageRegistry::READ_WRITE);

    // Initialize storage and modules
    testHelper.initializeModulesAndStorage();

    // Add a test case and mutate it
    StorageModule* storage = testHelper.getStorage();

    // test case 1
    StorageEntry* entry1 = storage->createNewEntry();
    char buff_1[3] = {'V','M','F'};
    entry1->allocateAndCopyBuffer(testCaseKey,3, buff_1);
    storage->saveEntry(entry1);

    // test case 2
    StorageEntry* entry2 = storage->createNewEntry();
    char buff_2[5] = {'V', 'A', 'D', 'E', 'R'};
    entry2->allocateAndCopyBuffer(testCaseKey,5, buff_2);
    storage->saveEntry(entry2);

    // mutate both test cases
    mutator->mutateTestCase(*storage, entry1, storage->createNewEntry(), testCaseKey);
    mutator->mutateTestCase(*storage, entry2, storage->createNewEntry(), testCaseKey);


    // assert that all test cases contain the token in the list of tokens
    std::string token = "/lib64/ld-linux-x86-64.so.2";
    StorageEntry* e;
    bool contains_correctly_mutated_testcase = false;
    int contains_correctly_mutated_testcase_count = 0;

    std::unique_ptr<Iterator> testcaseIter = storage->getNewEntries();
    while(testcaseIter->hasNext())
    {
        e = testcaseIter->getNext();
        std::string _buff = e->getBufferPointer(testCaseKey);
        GTEST_COUT << " testcase: " << _buff << std::endl;
        if (_buff.find(token) != std::string::npos) {
            contains_correctly_mutated_testcase |= true;
            contains_correctly_mutated_testcase_count += 1;
        }
    }
    ASSERT_TRUE(contains_correctly_mutated_testcase) << "Could not find " << token << " in any  test case";
    ASSERT_TRUE(contains_correctly_mutated_testcase_count == 2)  << "Not all testcases were mutated with token: " << token << " (Num test cases mutated: "<< contains_correctly_mutated_testcase_count <<")";
}


// Test user provided AFL dictionary
TEST(DictionaryMutatorTest, realisticallyConfiguredInputIntegrated)
{
    ModuleTestHelper testHelper = ModuleTestHelper();

    // Remove hard-coded `strings.dict` if present
    std::filesystem::remove_all(std::filesystem::path("strings.dict"));

    //Add mutators to testHelper
    MutatorModule* mutator = new DictionaryMutator("DictionaryMutator");
    testHelper.addModule(mutator);


    TestConfigInterface* config = testHelper.getConfig();

    //Setup config data
    std::string strings_path = "../test/unittest/inputs/DictionaryMutator/png.dict";
    config->setStringVectorParam("DictionaryMutator", "dictionaryPaths", {strings_path});
    config->addSubmodule("DictionaryMutator", mutator);

    StorageRegistry* registry = testHelper.getRegistry();
    int testCaseKey = registry->registerKey("TEST_CASE", StorageRegistry::BUFFER, StorageRegistry::READ_WRITE);

    // Initialize storage and modules
    testHelper.initializeModulesAndStorage();
    
    // Add a test case and mutate it
    StorageModule* storage = testHelper.getStorage();
    
    StorageEntry* entry1 = storage->createNewEntry();
    char buff_1[3] = {'V','M','F'};
    entry1->allocateAndCopyBuffer(testCaseKey,3, buff_1);
    storage->saveEntry(entry1);

    StorageEntry* entry2 = storage->createNewEntry();
    char buff_2[5] = {'V', 'A', 'D', 'E', 'R'};
    entry2->allocateAndCopyBuffer(testCaseKey,5, buff_2);
    storage->saveEntry(entry2);

    // mutate both test cases
    mutator->mutateTestCase(*storage, entry1, storage->createNewEntry(), testCaseKey);
    mutator->mutateTestCase(*storage, entry2, storage->createNewEntry(), testCaseKey);

    // assert that all test cases contain the token in the list of tokens
    std::vector<std::string> tokens = {
        "\x89PNG\x0d\x0a\x1a\x0a",
        "IDAT"
        "IEND",
        "IHDR",
        "PLTE",
        "bKGD",
        "cHRM",
        "fRAc",
        "gAMA",
        "gIFg",
        "gIFt",
        "gIFx",
        "hIST",
        "iCCP",
        "iTXt",
        "oFFs",
        "pCAL",
        "pHYs",
        "sBIT",
        "sCAL",
        "sPLT",
        "sRGB",
        "sTER",
        "tEXt",
        "tIME",
        "tRNS",
        "zTXt"
    };
    StorageEntry* e;
    bool contains_correctly_mutated_testcase = false;
    int contains_correctly_mutated_testcase_count = 0;

    std::unique_ptr<Iterator> testcaseIter = storage->getNewEntries();
    while(testcaseIter->hasNext())
    {
        e = testcaseIter->getNext();
        std::string _buff = e->getBufferPointer(testCaseKey);
        GTEST_COUT << " testcase: " << _buff << std::endl;
        for ( const auto& token : tokens ){
            if (_buff.find(token) != std::string::npos) {
                contains_correctly_mutated_testcase |= true;
                contains_correctly_mutated_testcase_count += 1;
            }
        }
    }
    ASSERT_TRUE(contains_correctly_mutated_testcase) << "Could not find any PNG tokens in any  test case";
    ASSERT_TRUE(contains_correctly_mutated_testcase_count == 2)  << "No testcases were mutated with token: with PNG tokens (Num test cases mutated: "<< contains_correctly_mutated_testcase_count <<")";
}

