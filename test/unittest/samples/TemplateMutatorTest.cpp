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
#include "ModuleTestHelper.hpp"
#include "StorageRegistry.hpp"
#include "StorageEntry.hpp"
#include "Logging.hpp"
#include "VmfUtil.hpp"
#include "ExecutorModule.hpp"

#include <filesystem>

using namespace vmf;
namespace fs = std::filesystem;

#define GTEST_COUT std::cerr << "[          ] [ INFO ]"

class TemplateMutatorTest : public ::testing::Test {
    protected:
        TemplateMutatorTest()
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
                fs::remove_all(OUTPUT_DIR);
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
        }
    
        void setup_configuration(std::string bcFilePath)
        {
            // This module requires the output directory parameter
            config->setOutputDir(OUTPUT_DIR);
    
            // Core dump check is disabled so this test can run on CI/CD
            config->setBoolParam(ExecModuleName, "enableCoreDumpCheck", false);
        }
    
        // relative to vader/build directory
        std::string OUTPUT_DIR = "./unittest_output/";
        
        ModuleTestHelper* testHelper; //testHelper will destroy all of the modules when it is destroyed
        ExecutorModule* executor;
        TestConfigInterface* config;
        StorageModule* storage;
        std::string ExecModuleName = "TemplateMutatorTest";
    
        //Storage fields that are read or written by this unit test
        int normalTag;
        int crashedTag;
        int hungTag;
        int hasNewCoverageTag;
        int testCaseKey;
        int execTimeKey;
};

    
TEST_F(TemplateMutatorTest, nominal){
    
}
