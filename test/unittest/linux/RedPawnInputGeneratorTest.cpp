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
#include "RedPawnInputGenerator.hpp"
#include "StorageEntry.hpp"
#include "AFLFlipBitMutator.hpp"
#include "AFLForkserverExecutor.hpp"
#include "ModuleTestHelper.hpp"
#include "StorageModuleStructures.hpp"
#include "SaveCorpusOutput.hpp"
#include "RedPawnCmpLogMap.hpp"

using namespace vmf;

#define GTEST_COUT std::cerr << "[          ] [ INFO ]"

class RedPawnInputGenTest : public ::testing::Test {
protected:

    RedPawnInputGenTest()
    {
        //This provides basic VMF logging, which is useful for debugging storage registration errors
        Logging::initConsoleLog();
    }

    void SetUp() override {
        testHelper = new ModuleTestHelper();

        config = testHelper->getConfig();
        storage = testHelper->getStorage();
        registry = testHelper->getRegistry();
        
        testCaseKey = registry->registerKey("TEST_CASE", StorageRegistry::BUFFER, StorageRegistry::READ_WRITE);
        cmpLogMapKey = registry->registerKey("CMPLOG_MAP_BITS", StorageRegistry::BUFFER_TEMP, StorageRegistry::WRITE_ONLY);

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

    /**
    * @brief Scans a CmpLogMap for the presence of a particular INS (instruction) entry,
    * specified as a compare size, compare type, number of hits and comparison values.
    * @return true if found and false if not found.
    */
    bool checkCmpMapForInsEntry(struct cmp_map * cmp_map, int target_size, int target_compare_type, int target_hits, uint64_t target_lhs, uint64_t target_rhs)
    {

        for (unsigned int i = 0; i < CMP_MAP_W; i++)
        {

            int hit_count = cmp_map->headers[i].hits;
            int compare_size = cmp_map->headers[i].shape + 1; // Shape starts at 0
            int compare_type = cmp_map->headers[i].attribute;

            if (hit_count == 0)
                continue;

            if (cmp_map->headers[i].type != CMP_TYPE_INS)
                continue;

            if (target_hits != hit_count)
                continue;

            if (target_size != compare_size)
                continue;

            if (target_compare_type != compare_type)
                continue;

            unsigned int num_hit_entries = std::min((int)hit_count, CMP_MAP_H);

            // Inspect each log entry we have at index i
            for (unsigned int j=0; j < num_hit_entries; j++)
            {
                uint64_t lhs = cmp_map->log[i][j].v0;
                uint64_t rhs = cmp_map->log[i][j].v1;

                // Allow either handedness to match
                if ((lhs == target_lhs && rhs == target_rhs) ||
                    (rhs == target_lhs && lhs == target_rhs))
                {
                    return true;
                }
            }
        }

        GTEST_COUT << "Ins comparison not found.\n";
        return false;
    }

    /**
    * @brief Scans a CmpLogMap for the presence of a particular RTN (routine) entry,
    * specified as the comparison values of two short strings (char[32]).
    * @return true if found and false if not found.
    */
    bool checkCmpMapForRtnEntry(struct cmp_map * cmp_map, char lhs[32], char rhs[32])
    {

        for (unsigned int i = 0; i < CMP_MAP_W; i++)
        {
            int hit_count = cmp_map->headers[i].hits;
            if (hit_count == 0)
                continue;

            if (cmp_map->headers[i].type != CMP_TYPE_RTN)
                continue;

            unsigned int num_hit_entries = std::min((int)hit_count, CMP_MAP_H);

            for (unsigned int j=0; j < num_hit_entries; j++)
            {
                // Cast log entry into a cmpfun_operands
                struct cmpfn_operands* func_operands = (struct cmpfn_operands*) &cmp_map->log[i][j];

                // Allow either handedness to match
                if ((memcmp(lhs, func_operands->v0, 32) == 0 && memcmp(rhs, func_operands->v1, 32) == 0) ||
                    (memcmp(lhs, func_operands->v1, 32) == 0 && memcmp(rhs, func_operands->v0, 32) == 0))
                {
                    return true;
                }
            }
        }

        GTEST_COUT << "Routine pattern not found.\n";
        return false;
    }

    ModuleTestHelper* testHelper; // testHelper will destroy all of the modules when it is destroyed
    TestConfigInterface* config;
    StorageModule* storage;
    StorageRegistry* registry;
    std::string ModuleName = "RedPawnInputGenerator";

    // Storage fields that are read or written by this unit test
    int testCaseKey;
    int cmpLogMapKey;
};

/**
* @brief Validates the contents of a CmpLogMap retrieved by running a SUT against
* expected hardcoded values. Requires the following comparison data entries to be found:
* 1) a 4 byte compare of AAAA == 0xDEADBEEF that is hit once
* 2) an 8 byte compare of BBBBBBBB == 0xDEADBEEFDEADBEEF that is hit once
* 3) a 4 byte compare of 0 < 12 for an entry that is hit 12 times (loop back edge)
* 4) a string compare of "teststring" to "hellothere"
*/
TEST_F(RedPawnInputGenTest, DISABLED_validateCmplogMap)
{

    // Setup and init
    ExecutorModule* executorCmpLog = new AFLForkserverExecutor("cmplogExecutor");
    ExecutorModule* executorDefault = new AFLForkserverExecutor("colorizationExecutor");
    testHelper->addModule(executorCmpLog);
    testHelper->addModule(executorDefault);
    config->addSubmodule(ModuleName,executorCmpLog);
    config->addSubmodule(ModuleName,executorDefault);

    // Execution of the UT is expected to occur within the `build` directory for VADER
    config->setStringVectorParam("cmplogExecutor", "sutArgv", {"build_artifacts/cmpmaptest_cmplog", "@@"});
    config->setStringVectorParam("colorizationExecutor", "sutArgv", {"build_artifacts/cmpmaptest", "@@"});
    config->setBoolParam("cmplogExecutor", "cmpLogEnabled", true);
    config->setIntParam("cmplogExecutor", "memoryLimitInMB", 400);
    config->setBoolParam("cmplogExecutor", "writeStats", false);
    config->setBoolParam("cmplogExecutor","enableCoreDumpCheck", false);
    config->setBoolParam("colorizationExecutor","enableCoreDumpCheck", false);

    Init();

    // Calibrate
    GTEST_COUT << "ValidateCmplogMap creating and running calibration on cmpmaptest binary\n";
    char buffCal[] = {'C','A','L'};
    StorageEntry* entry = storage->createNewEntry();
    entry->allocateAndCopyBuffer(testCaseKey,3, buffCal);
    std::unique_ptr<Iterator> newEntries = storage->getNewEntries();
    executorDefault->runCalibrationCases(*storage, newEntries); 

    // Run a testcase on cmplog executor
    GTEST_COUT << "ValidateCmplogMap running cmplog executor\n";
    char buff1[32];
    memset(buff1, 0, sizeof(buff1));
    strncpy(buff1, "AAAABBBBBBBBteststring", 24);
    StorageEntry* entry1 = storage->createNewEntry();
    entry1->allocateAndCopyBuffer(testCaseKey,sizeof(buff1), buff1);
    executorCmpLog -> runTestCase(*storage, entry1);

    // Assert that we have a cmplog map buffer and that it is the right size
    ASSERT_TRUE(entry1->hasBuffer(cmpLogMapKey));
    ASSERT_EQ(entry1->getBufferSize(cmpLogMapKey), sizeof(struct cmp_map));

    // Cast the buffer to an actual struct cmp_map we can inspect
    cmp_map* cmp_map = (struct cmp_map *) entry1 -> getBufferPointer(cmpLogMapKey);

    // Check that the map contains a 4 byte compare of AAAA == 0xDEADBEEF that is hit once
    ASSERT_TRUE(checkCmpMapForInsEntry(cmp_map, 4, CMP_TYPE_EQ, 1, 0x41414141, 0xDEADBEEF));

    // Check that the map contains an 8 byte compare of BBBBBBBB == 0xDEADBEEFDEADBEEF that is hit once
    ASSERT_TRUE(checkCmpMapForInsEntry(cmp_map, 8, CMP_TYPE_EQ, 1, 0x4242424242424242, 0xDEADBEEFDEADBEEFL));

    // Check that the map contains a 4 byte compare of 0 < 12 for an entry that is hit 12 times
    // This is the loop back edge in the program.
    ASSERT_TRUE(checkCmpMapForInsEntry(cmp_map, 4, CMP_TYPE_LT, 12, 0, 12));

    // Check that the map contains a string compare of "teststring" to "hellothere"
    char lhs[32], rhs[32];
    memset(lhs, 0, 32);
    memset(rhs, 0, 32);
    strncpy(rhs, "teststring", 32);
    strncpy(lhs, "hellothere", 32);
    ASSERT_TRUE(checkCmpMapForRtnEntry(cmp_map, rhs, lhs));

    // Lastly count up the number of entries that we found in the cmplog map
    int num_cmplog_entries = 0;
    for (unsigned int i = 0; i < CMP_MAP_W; i++)
    {
        if (cmp_map->headers[i].hits > 0)
        {
            num_cmplog_entries++;
        }
    }

    // Some compiler versions create one more compare as part of the while loop. We allow
    // but don't require it. It's an extra equality check between 0 an the loop max (12).
    bool hasExtraLoopCompare = checkCmpMapForInsEntry(cmp_map, 4, CMP_TYPE_EQ, 1, 0, 12);

    // Then lastly we make sure that there aren't any unexpected entries.
    ASSERT_TRUE(num_cmplog_entries == 4 || (num_cmplog_entries == 5 && hasExtraLoopCompare));
}
