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
#include "TrivialSeedInitialization.hpp"
#include "TestConfigInterface.hpp"

using namespace vmf;

#define GTEST_COUT std::cerr << "[          ] [ INFO ]"


TEST(TrivialSeedTest, nominal)
{
    ModuleTestHelper testHelper = ModuleTestHelper();
    TrivialSeedInitialization* ts = new TrivialSeedInitialization("TrivialSeedInitialization");
    testHelper.addModule(ts);

    StorageRegistry* registry = testHelper.getRegistry();
    int testCaseKey = registry->registerKey("TEST_CASE", StorageRegistry::BUFFER, StorageRegistry::READ_WRITE);

    testHelper.initializeModulesAndStorage();

    StorageModule* storage = testHelper.getStorage();

    ts->run(*storage);

    StorageEntry* e;
    std::unique_ptr<Iterator> testcaseIter = storage->getNewEntries();
    char expected_seed[] = {'h', 'e', 'l', 'l', 'o'};
    int expected_buff_len = 5;
    int num_testcases = 0;
    if (testcaseIter->hasNext())
    {
        e = testcaseIter->getNext();
        std::string _buff = e->getBufferPointer(testCaseKey);
        GTEST_COUT << " testcase: '" << _buff.c_str() << "' (length: " << strlen(_buff.c_str()) << ") (expected: '" << expected_seed << "' length: " << strlen(expected_seed) << ")" << std::endl;
        for (int i = 0; i < expected_buff_len; i++){
            ASSERT_EQ(_buff.c_str()[i], expected_seed[i]);
        }
        num_testcases++;
    } else {
        FAIL() << "Expected test case not found";
    }

    ASSERT_EQ(num_testcases, 1) << "More than one test case was produced by the trivial seed initializer";
    // TrivialSeedInitialization destruction handled as part of teardown of ModuleTestHelper
}
