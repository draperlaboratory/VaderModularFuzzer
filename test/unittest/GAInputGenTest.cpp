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
#include "GeneticAlgorithmInputGenerator.hpp"
#include "ModuleTestHelper.hpp"
#include "AFLFlipBitMutator.hpp"

using namespace vmf;

#define GTEST_COUT std::cerr << "[          ] [ INFO ]"

class GAInputGenTest : public ::testing::Test {
protected:

    GAInputGenTest()
    {
        //This provides basic VMF logging, which is useful for debugging storage registration errors
        Logging::initConsoleLog();
    }

    void SetUp() override {
        testHelper = new ModuleTestHelper();
        //Construct module under test
        GAInputGen = new GeneticAlgorithmInputGenerator("GeneticAlgorithmInputGenerator");
        testHelper->addModule(GAInputGen);

        config = testHelper->getConfig();
        storage = testHelper->getStorage();
    }

    void TearDown() override {
        delete testHelper;
        //The ModuleTestHelper destructor will also delete any added modules
    }

    //Module specific test setup
    void add3MutatorSubmodulesAndInitEverything()
    {
        //Add mutators to testHelper
        MutatorModule* mutator1 = new AFLFlipBitMutator("mutator1");
        MutatorModule* mutator2 = new AFLFlipBitMutator("mutator2");
        MutatorModule* mutator3 = new AFLFlipBitMutator("mutator3");

        testHelper->addModule(mutator1);
        testHelper->addModule(mutator2);
        testHelper->addModule(mutator3);

        //Setup config data
        config->addSubmodule(mutator1);
        config->addSubmodule(mutator2);
        config->addSubmodule(mutator3);

        //Register for relevant storage handles that we need to read or write within the unit test
        //(the module's registerStorageNeeds method is called automatically by the ModuleTestHelper)
        StorageRegistry* registry = testHelper->getRegistry();
        normalTag = registry->registerTag("RAN_SUCCESSFULLY", StorageRegistry::WRITE_ONLY);
        testCaseKey = registry->registerKey("TEST_CASE", StorageRegistry::BUFFER, StorageRegistry::READ_WRITE);

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

    
    ModuleTestHelper* testHelper; //testHelper will destroy all of the modules when it is destroyed
    InputGeneratorModule* GAInputGen;
    TestConfigInterface* config;
    StorageModule* storage;

    //Storage fields that are read or written by this unit test
    int normalTag;
    int testCaseKey;

};

TEST_F(GAInputGenTest, basicMutationTest)
{
    add3MutatorSubmodulesAndInitEverything();
    
    //Add some seed test cases to storage
    //These all need to be saved and marked with the normal tag in order to be used
    char buff1[] = {'V','M','F'};
    StorageEntry* entry1 = storage->createNewEntry();
    entry1->allocateAndCopyBuffer(testCaseKey,3,buff1);
    entry1->addTag(normalTag);
    storage->saveEntry(entry1);

    char buff2[] = {'T','E','S','T'};
    StorageEntry* entry2 = storage->createNewEntry();
    entry2->allocateAndCopyBuffer(testCaseKey,4,buff2);
    entry2->addTag(normalTag);
    storage->saveEntry(entry2);

    //This method must be called to make the entries above no longer new
    storage->clearNewAndLocalEntries();

    //Now test the module
    GAInputGen->addNewTestCases(*storage);

    //There should be 3 new entries in storage (one for each mutator)
    int size = storage->getNewEntries()->getSize();
    ASSERT_EQ(size,3);
}