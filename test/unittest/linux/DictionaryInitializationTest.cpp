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
#include "IterativeController.hpp"
#include "SimpleStorage.hpp"
#include "RuntimeException.hpp"
#include "ModuleTestHelper.hpp"
#include "DictionaryInitialization.hpp"
#include "DictionaryMutator.hpp"
#include "TestConfigInterface.hpp"

using namespace vmf;

#define GTEST_COUT std::cerr << "[          ] [ INFO ]"


TEST(DictionaryInitializationTest, missingSutPath)
{
    DictionaryInitialization testHelper = DictionaryInitialization("DictionaryInitialization");
    try {
        TestConfigInterface config = TestConfigInterface();
        testHelper.init(config);
        FAIL() << "Failed to throw expected exception";
    } catch (RuntimeException e) {
        EXPECT_EQ( e.getErrorCode(), RuntimeException::OTHER );
        EXPECT_STREQ( e.getReason().c_str(), "getParam failed because the param value was not yet set" );
    } catch (...) {
        FAIL() << "Unrecognized exception";
    }
}


TEST(DictionaryInitializationTest, nonExistentOutputPath)
{
    DictionaryInitialization testHelper = DictionaryInitialization("DictionaryInitialization");
    try {
        SimpleStorage storage = SimpleStorage("storage");
        TestConfigInterface config = TestConfigInterface();

        std::string output_dir = "../../test/unittest/outputs/non-existent";
        std::vector<std::string> sutArgv = {"test/haystackSUT/haystack"};
        std::vector<std::string> dictionary_paths = {"../../test/unittest/outputs/strings-initializer.txt"};

        config.setOutputDir(output_dir);
        config.setStringVectorParam("DictionaryInitialization", "sutArgv", sutArgv);

        testHelper.init(config);
        testHelper.run(storage);

        // Test that generated strings file is parsable by the Dictionary Mutator
        std::vector<char*> tokens;
        DictionaryMutator::get_tokens(dictionary_paths[0], tokens);
        FAIL() << "Failed to throw expected exception";
    } catch (RuntimeException e) {
        EXPECT_EQ(e.getErrorCode(), RuntimeException::OTHER);
        EXPECT_STREQ( e.getReason().c_str(), "Non-existent output directory");
    } catch (...) {
        FAIL() << "Unrecognized exception";
    }
}


TEST(DictionaryInitializationTest, correctlyConfigured)
{
    DictionaryInitialization testHelper = DictionaryInitialization("DictionaryInitialization");
    SimpleStorage storage = SimpleStorage("storage");
    TestConfigInterface config = TestConfigInterface();
    
    // Remove hard-coded `strings.dict` if present
    std::filesystem::remove_all(std::filesystem::path("strings.dict"));

    std::string output_dir = ".";
    std::vector<std::string> sutArgv = {"../../test/haystackSUT/haystack"};
    std::vector<std::string> strings_path = {"./strings.dict"};

    config.setOutputDir(output_dir);
    config.setStringVectorParam("DictionaryInitialization", "sutArgv", sutArgv);

    testHelper.init(config);
    testHelper.run(storage);

    // Test that generated strings file is parsable by the Dictionary Mutator
    std::vector<char*> tokens;
    DictionaryMutator::get_tokens(strings_path[0], tokens);

    for (char* token : tokens) {
        delete[] token;
    }
}

