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
 *
 * ===========================================================================*/

#pragma once

#include "FeedbackModule.hpp"
#include "StorageRegistry.hpp"
#include <map>
#include <memory>

namespace vmf
{

/**
 * @brief FeedbackModule to examine results from a differential campaign of AFLForkserverExecutors.
 * AFLDiffFeedback requires as inputs the TEST_CASE buffer as well as some of the 
 * execution results. The module outputs a FITNESS value in storage.
 */
class AFLDiffFeedback : public FeedbackModule {
public:
   /**
    * @brief Builder method to support the ModuleFactory
    * Constructs an instance of this class
    * @return Module* 
    */
    static Module* build(std::string name);

    /**
    * @brief Initialization method
    * Reads in all configuration options for this class, including the given Executor names.
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
     * @warning This module does not support feedback on single testcase results.
     */
    virtual void evaluateTestCaseResults(StorageModule& storage, std::unique_ptr<Iterator>& entries);

    /**
     * @brief Evaluate the test case results from all executors
     * This method:
     * 1) computes and saves the fitness to the storage entry
     * 2) saves any other values of interest to the storage entry, including tagging the entry if relevant
     * 3) determines if the test case shared across the executors is interesting enough to save in 
     *      long term storage (and save the entry if it is)
     * 
     * @param storage: storage module 
     * @param entries: a map from each executor to respective entries
     */
    virtual void evaluateDiffTestCaseResults(StorageModule& storage, std::vector<std::unique_ptr<Iterator>>& entries); 

    /**
     * @brief Construct a new AFLDiffFeedback object
     * 
     * @param name the module name
     */
    AFLDiffFeedback(std::string name);

    virtual ~AFLDiffFeedback();
protected:
    enum end_state {crash, hang, safe};
    const std::string end_state_str[3] = {"CRASH", "HANG", "SUCCESS"};

    /**
     * @brief Computes the fitness for the provided differential test cases
     * 
     * @param storage the storage module
     * @param entries the test cases that were just executed
     * @param covg testcase coverage
     * @param execT testcase execution time
     * @param deviants testcases that exhibited differential behavior
     *
     * @return float the fitness
     */
    virtual std::vector<float> computeDiffFitness(std::vector<StorageEntry*>& entries, 
        std::vector<unsigned int>& covg, std::vector<unsigned int>& execT, std::vector<int>& sizes, 
        std::vector<unsigned long> deviants);

    /**
     * @brief Helper method to convert microsecond execution time to milliseconds
     * This method is used to ensure consistency with the AFL++ fitness algorithm,
     * which uses millisecond time precision.  The minimum returned execution time
     * from this method is 1ms.
     * 
     * @param e the test case to examine
     * @return unsigned int the execution time in milliseconds
     */
    unsigned int getExecTimeMs(StorageEntry* e);

    /**
     * @brief Helper method to determine which entries, if any, resulted DIFFERENTLY from the 
     * voted on output.
     *
     * @param batch one test case per executor
     * @param def default value in case of voting failure, aka end state of trusted executor
     * @return vector representing the index of deviant entries in the batch
     */
    std::vector<unsigned long> findEndStateDeviants(std::vector<StorageEntry*>& batch, AFLDiffFeedback::end_state def, bool anyHasCovg);

    /** 
     * @brief Helper method to promote DRY lookups of an entry's endState tag
     *
     * @param e StorageEntry to lookup
     * @return end_state enum of CRASH, HUNG, or SAFE (ran successfully)
     */
    AFLDiffFeedback::end_state getEndState(StorageEntry* e);

    /**
     * @brief Helper method to find an entry's corresponding ExecutorModule name
     *
     * @param e StorageEntry to lookup
     * @return ExecutorModule name
     */
    std::string getExecName(StorageEntry* e);

    /**
     * @brief Helper method to ensure that only Entries from the same input buffer are compared
     * Compares Entry batch ID numbers to ensure that differential end states originate from
     * a shared input.
     * 
     * @param batch comparable storage entries
     * @return if entries are from the same batch
     * @throws RuntimeException: StorageIterator returned testcases from the same round that did not 
     *  have matching inputs
     */
    bool assertSharedBatch(std::vector<StorageEntry*>& batch);

protected:
    std::string outputDir; ///< Location of output directory
    std::string expectedSUT; ///< Name of reference SUT for end-state source of truth

    int testCaseKey; ///< Handle for the "TEST_CASE" field
    int execTimeKey; ///< Handle for the "EXEC_TIME_US" field
    int coverageByteCountKey; ///< Handle for the "COVERAGE_COUNT" field
    int batchNumIdKey; ///< Handle for the "ENTRY_BATCH_NUM" field
    int fitnessKey; ///< Handle for the "FITNESS" field
    int hasNewCoverageTag; ///< Handle for the "HAS_NEW_COVERAGE" tag
    int crashedTag; ///< Testcase crashed
    int hungTag; ///< Testcase did not exit
    int expectedSUTTag; ///< Designated source of truth
    int deviantTag; ///< Testcase did not exit with expected code
    std::map<std::string, int> execNameTags;

    std::vector<float> avgExecTimePerExec; ///< The average execution time per executor (for test cases that have been eval'd)
    std::vector<float> maxExecTimePerExec;
    std::vector<float> avgTestCaseSizePerExec;
    std::vector<float> maxTestCaseSizePerExec;
    float sizeFitnessWeight; ///< A configurable weight to apply to the size factor in computing fitness. Must be >=0.0
    float speedFitnessWeight; ///< A configurable weight to apply to the speed factor in computing fitness. Must be >=0.0
    float diffFitnessWeight; ///< A configurable weight to apply to the differential factor in computing fitness. Must be >=0.0
    int numTestCases; ///< The total number of test cases that have been evaluated

    bool useCustomWeights; ///< Whether or not custom weights are enabled
    bool isExpectedReal; ///< Whether or not the user provided a valid reference SUT in the config
};
}