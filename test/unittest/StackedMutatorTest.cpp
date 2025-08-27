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
#include "StackedMutator.hpp"
#include "RuntimeException.hpp"

// Include sample mutators
#include "AFLFlipBitMutator.hpp"
#include "AFLFlip2BitMutator.hpp"
#include "AFLFlip4BitMutator.hpp"

#include <filesystem>
#include <tuple>

using namespace vmf;

using ::testing::Combine;
using ::testing::Values;
using ::testing::Bool;

#define GTEST_COUT std::cerr << "[          ] [ INFO ]"

// Testing constants

// mutator selection distribution values
std::vector<float> uniform_distribution = {0.333f, 0.333f, 0.334f};
std::vector<float> non_uniform_distribution = {0.1665f, 0.1665f, 0.668f};

// possible mutator pools
std::vector<MutatorModule*> empty_mutator_pool = {};
    std::vector<MutatorModule*> mutator_pool = {
    new AFLFlipBitMutator("AFLFlipBitMutator"),
    new AFLFlip2BitMutator("AFLFlip2BitMutator"),
    new AFLFlip4BitMutator("AFLFlip4BitMutator")
};


class StackedMutatorTest : public ::testing::TestWithParam<std::tuple<
    std::vector<MutatorModule*>, bool, int, std::vector<float>, std::string>
> {
    protected:
        StackedMutatorTest()
        {
            //This provides basic VMF logging, which is useful for debugging storage registration errors
            Logging::initConsoleLog();
        }
    
        void SetUp() override {
            std::tie(mutators, randomStackSize, stackSize, distribution, mutatorSelectorAlgorithm) = GetParam();
            testHelper = new ModuleTestHelper();
            config = testHelper->getConfig();
            storage = testHelper->getStorage();
            
            setup_configuration();
            configure_storage();

    
            // create output directory freshly for each test case
            VmfUtil::createDirectory(OUTPUT_DIR.c_str());
        }
    
        void TearDown() override {
            // remove output dir at tear down to run each test with fresh output dir
            if (std::filesystem::exists(OUTPUT_DIR)) {
                std::filesystem::remove_all(OUTPUT_DIR);
            }
            //The ModuleTestHelper destructor will also delete any added modules including all submodules in the mutator pool
            delete testHelper;
        }
    
        //Module specific test setup
        void setupExecutorTest()
        {
            //Initialize everything using the ModuleTestHelper class
            testHelper->initializeModulesAndStorage();
        }
    
        void configure_storage()
        {
            // Register for relevant storage handles that we need to read or write within the unit test
            //(the module's registerStorageNeeds method is called automatically by the ModuleTestHelper)
            registry = testHelper->getRegistry();
            testCaseKey = registry->registerKey("TEST_CASE", StorageRegistry::BUFFER, StorageRegistry::WRITE_ONLY);
        }
    
        void setup_configuration()
        {
            // This module requires the output directory parameter
            config->setOutputDir(OUTPUT_DIR);
    
            // Core dump check is disabled so this test can run on CI/CD
            config->setBoolParam(ExecModuleName, "enableCoreDumpCheck", false);
        }

        void verify_selection(size_t stack_used_size, std::vector<MutatorModule*> stack_used)
        {
            if (mutatorSelectorAlgorithm != "staticMutatorSelector")
                for (size_t i = size_t(0); i < stack_used_size; i++)
                {
                    bool found = false;
                    for (size_t j = size_t(0); j < num_mutators; j++)
                        if (stack_used[i]->getModuleName().compare(mutators[j]->getModuleName()) == 0)
                            found = true;
                    ASSERT_TRUE(found) << "Used mutator other than those that were user provided: " << stack_used[i]->getModuleName();
                }
            else
                for (int i = 0; i < stack_used_size; i++)
                    ASSERT_EQ(stack_used[i]->getModuleName(), mutators[i % num_mutators]->getModuleName());
        }

        void verify_distribution()
        {
            if (false)
            {
                // Prepare map of counts
                std::map<std::string, double> counts = {
                    {"all", 0.0},
                    {"AFLFlipBitMutator", 0.0},
                    {"AFLFlip2BitMutator", 0.0},
                    {"AFLFlip4BitMutator", 0.0},
                };

                // Randomly mutate for numTrial iterations
                for (int i = 0; i < numTrials; i++)
                {
                    // Attempt to mutate a testcase
                    char buff[9] = {"haystack"};
                    StorageEntry* e = storage->createNewEntry();
                    StorageEntry* o = storage->createNewEntry();
                    e->allocateAndCopyBuffer(testCaseKey, 9, buff);
                    mutator->mutateTestCase(*storage, e, o, testCaseKey);

                    std::vector<MutatorModule*> stack_used = mutator->getStack();

                    for (size_t j = 0; j < stack_used.size(); j++)
                    {
                        counts["all"]++;
                        counts[stack_used[j]->getModuleName()]++;
                    }
                }

                // Check observed distribution
                for (int i = 0; i < num_mutators; i++)
                {
                    ASSERT_NEAR((counts[mutators[i]->getModuleName()] / counts["all"]), distribution[i], tolerance);
                }
            }
        }

        // relative to vader/build directory
        // All pointers will be deleted up call to TearDown function
        std::string OUTPUT_DIR = "unittest_output";
        ModuleTestHelper* testHelper; //testHelper will destroy all of the modules when it is destroyed
        ExecutorModule* executor;
        TestConfigInterface* config;
        StorageModule* storage;
        StorageRegistry *registry;
        StackedMutator* mutator;
        std::string ExecModuleName = "StackedMutatorTest";
    
        // testing parameters
        bool randomStackSize;
        std::vector<float> distribution;
        int stackSize;
        std::vector<MutatorModule*> mutators;
        std::string mutatorSelectorAlgorithm;
        int numTrials = 100000;
        double tolerance = 1e-4;

        //Storage fields that are read or written by this unit test
        int normalTag;
        int crashedTag;
        int hungTag;
        int hasNewCoverageTag;
        int testCaseKey;
        int execTimeKey;

        // implied testing information (unique value to each test case)
        size_t num_mutators;
};

TEST_P(StackedMutatorTest, testFunctionality)
{
    try
    {
        mutator = new StackedMutator(ExecModuleName);
        num_mutators = mutators.size();
        testHelper->addModule(mutator);
        for ( auto &m : mutators ){
            config->addSubmodule(ExecModuleName, m);
            testHelper->addModule(m);
        }
        config->setBoolParam(ExecModuleName, "randomStackSize", randomStackSize);
        config->setIntParam(ExecModuleName, "stackSize", stackSize);

        // custom distribution is a configuration of the selector algorithm used
        config->setStringParam(ExecModuleName, "mutatorSelector", mutatorSelectorAlgorithm);
        config->setFloatVectorParam(ExecModuleName, "mutatorSelectionDistribution", distribution);

        testHelper->initializeModulesAndStorage();

        // Attempt to mutate a testcase
        char buff[9] = {"haystack"};
        StorageEntry* e = storage->createNewEntry();
        StorageEntry* o = storage->createNewEntry();
        e->allocateAndCopyBuffer(testCaseKey, 9, buff);
        mutator->mutateTestCase(*storage, e, o, testCaseKey);

        // Assert that they are not equal
        ASSERT_NE(e->getBufferPointer(testCaseKey), o->getBufferPointer(testCaseKey)) << " Testcase not mutated: " << e->getBufferPointer(testCaseKey) << " (original), " << o->getBufferPointer(testCaseKey) << " (mutated)";

        std::vector<MutatorModule*> stack_used = mutator->getStack();
        size_t stack_used_size = stack_used.size();

        // Verify stack length
        if (randomStackSize)
            ASSERT_LE(stack_used_size, stackSize);
        else
            ASSERT_EQ(stack_used_size, stackSize);

        // Verify mutator selection 
        verify_selection(stack_used_size, stack_used);

        // Verify mutator selection distribution
        verify_distribution();
    }
    catch (RuntimeException e)
    {
        if ("Cannot declare a mutation stack with no mutators" == e.getReason())
        {
            ASSERT_EQ(RuntimeException::USAGE_ERROR, e.getErrorCode());
            ASSERT_EQ(mutators, std::vector<MutatorModule*>({}));
        }
        else if ("Cannot declare a zero-length mutation stack" == e.getReason())
        {
            ASSERT_EQ(RuntimeException::USAGE_ERROR, e.getErrorCode());
            ASSERT_EQ(stackSize, 0);
        }
        else
        {
           FAIL() << "Unexpected RuntimeException thrown: " << e.getReason();
        }
    }
    catch (...)
    {
        FAIL() << "Unexpected exception thrown";
    }
}

INSTANTIATE_TEST_SUITE_P(
    StackedMutatorFailureCases,
    StackedMutatorTest,
    Values(
        // Non
        std::make_tuple(mutator_pool, false, 0, std::vector<float>({1.0,1.0,1.0}), "staticMutatorSelector"),
        
        // Case where mutator selection distribution doesn't map to mutator pool
        std::make_tuple(mutator_pool, false, 0, std::vector<float>({1.0,1.0}), "staticMutatorSelector")
    )
);


INSTANTIATE_TEST_SUITE_P(
    StackedMutatorConfigurations,
    StackedMutatorTest,
    Combine(
        Values(empty_mutator_pool, mutator_pool), // Pool of mutators provided
        Bool(), // randomize stack size
        Values(0, 3, 5),  // stack size
        Values(uniform_distribution, non_uniform_distribution), // uniform or non-uniform mutator selection distribution 
        Values("staticMutatorSelector", "uniformMutatorSelector", "WeightedRandomSelector") // Mutator selector algorithm choices
    )
);
