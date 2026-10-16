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
#pragma once

#include "InputGeneratorModule.hpp"
#include "MOPT.hpp"
#include "ExecutorModule.hpp"

namespace vmf
{

/**
 * @brief This InputGeneratorModule is an optimized mutator selection approach that is based on the MOpt algorithm.
 * 
 * See https://www.usenix.org/system/files/sec19-lyu.pdf
 * 
 * This module uses the RAN_SUCCESSFULLY tag to select only test cases with a normal execution
 * pattern as the basis of mutation.  It uses MUTATOR_ID to track which MutatorModule submodule
 * was used to create each TEST_CASE, and adjusts how frequently it uses each mutator based on
 * the observed performance of the resulting test cases.
 * @image html CoreModuleDataModel_4.png width=800px
 * @image latex CoreModuleDataModel_4.png width=6in
 */
class DiffInputGenerator: public InputGeneratorModule
{
public:
    /**
    * @brief Builder method to support the ModuleFactory
    * Constructs an instance of this class
    * @return Module* 
    */
    static Module* build(std::string name);

    /**
    * @brief Initialization method
    * Reads in all configuration options for this class
    * 
    * @param config 
    */
    virtual void init(ConfigInterface& config);

    /**
     * @brief Notify Storage module of necessary data needs
     * Create output keys and copies of essential input keys and tags.
     *
     * @param registry
     */
    virtual void registerStorageNeeds(StorageRegistry& registry);

    /**
     * @brief Generate new testcases and copy them for each testcase
     *
     * @param storage
     */
    virtual void addNewTestCases(StorageModule& storage);

    virtual bool examineTestCaseResults(StorageModule& storage);

    /**
    * @brief Construct a new Genetic Algorithm Input Generator module
    * 
    * @param name the name of the module
    */
    DiffInputGenerator(std::string name);
    virtual ~DiffInputGenerator();
private:

    /**
    * @brief Helper method to select the base entry to mutate
    * 
    * This implementation uses a weighted random selection that favors entries with lower indices
    * 
    * @param storage the storage module 
    * @return StorageEntry* the base entry to use
    */
    StorageEntry* selectBaseEntry(StorageModule& storage);

    MOPT* mopt;
    unsigned int testCasesRan; ///< Number of test cases run across all executors
    unsigned long long batchNum; ///< Batch number for a uniquely generated test case
    int moptMutatorIdKey;
    int mutatorIdKey;
    std::vector<int> executorIdTags; ///< ID Tags for Executor modules
    int normalTag; ///< Test case RAN_SUCCESSFULLY
    int testCaseKey; ///< Input buffer key for StorageEntry
    int batchNumIdKey; ///< Batch number key for StorageEntry

    std::vector<MutatorModule*> mutators; ///< The list of mutators being managed by this input generator
    std::vector<ExecutorModule*> executors; ///< The list of executors present in this fuzzing campaign

    std::vector<int> mutatorStats;
    std::vector<int> mutatorStatsTotalTestCases;
};
}
