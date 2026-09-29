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
#include "ModuleTestHelper.hpp"
#include "StorageModuleStructures.hpp"
#include "SaveCorpusOutput.hpp"

// Then include in any input generator specific headers like so:
// #include "GeneticAlgorithmInputGenerator.hpp"
// #include "AFLFlipBitMutator.hpp"


using namespace vmf;

#define GTEST_COUT std::cerr << "[          ] [ INFO ]"

class InputGenTest : public ::testing::Test {
protected:

    InputGenTest(InputGeneratorModule* ig, std::string ModuleName)
    {
        //This provides basic VMF logging, which is useful for debugging storage registration errors
        Logging::initConsoleLog();
    }

    void SetUp() override {
        testHelper = new ModuleTestHelper();

        // Construct module under test
        // IG = new GeneticAlgorithmInputGenerator(ModuleName);
        // testHelper->addModule(IG);

        config = testHelper->getConfig();
        storage = testHelper->getStorage();
        registry = testHelper->getRegistry();
        
        crashedTag = registry->registerTag("CRASHED", StorageRegistry::WRITE_ONLY);
        hungTag = registry->registerTag("HUNG", StorageRegistry::WRITE_ONLY);
        config->setOutputDir(".");


    }

    void TearDown() override {
        delete testHelper;
        //The ModuleTestHelper destructor will also delete any added modules
    }

    void Init() {
        // Initialize everything using the ModuleTestHelper class
        try
        {
            testHelper->initializeModulesAndStorage();
        }
        catch(RuntimeException e)
        {
            FAIL() << "Storage or module initialization failed due to error -- " << e.getReason();
        }
    }

    ModuleTestHelper* testHelper; // testHelper will destroy all of the modules when it is destroyed
    InputGeneratorModule* IG;
    TestConfigInterface* config;
    StorageModule* storage;
    StorageRegistry* registry;
    std::string ModuleName = "InputGenerator";

    // Storage fields that are read or written by this unit test
    int testCaseKey;
    int testcaseParentIdKey;
    int generationKey;
    int numChildrenKey;
    int mutatorIdKey;
    
    // Tags for testcase determination
    int normalTag;
    int crashedTag;
    int hungTag;
};

TEST_F(InputGenTest, basicMutationTest)
{
    // Then implement your test
}
