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


#include "FeedbackModule.hpp"

namespace vmf
{

/**
 * @brief FeedbackModule to examine results from AFLForkserverExecutor.
 * AFLFeedback requires as inputs the TEST_CASE buffer as well as some of the 
 * execution results.  It outputs a FITNESS value in storage.
 * @image html CoreModuleDataModel_2.png width=800px
 * @image latex CoreModuleDataModel_2.png width=6in
 */
class AFLFeedback : public FeedbackModule {
public:

    static Module* build(std::string name);
    virtual void init(ConfigInterface& config);

    virtual void registerStorageNeeds(StorageRegistry& registry);
    virtual void evaluateTestCaseResults(StorageModule& storage, std::unique_ptr<Iterator>& entries); 

    /**
     * @brief Construct a new AFLFeedback object
     * 
     * @param name the module name
     */
    AFLFeedback(std::string name);

    virtual ~AFLFeedback();
protected:

    /**
     * @brief Computes the fitness for the provided test case
     * This method is intended to be extended by subclasses that want a different fitness
     * computation algorithm.
     * 
     * @param storage the storage module
     * @param e the test case that was just executed
     * @return float the fitness
     */
    virtual float computeFitness(StorageModule& storage, StorageEntry* e);

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
protected:
    std::string outputDir; ///< Location of output directory

    int testCaseKey; ///< Handle for the "TEST_CASE" field
    int execTimeKey; ///< Handle for the "EXEC_TIME_US" field
    int coverageByteCountKey; ///< Handle for the "COVERAGE_COUNT" field
    int fitnessKey; ///< Handle for the "FITNESS" field
    int hasNewCoverageTag; ///< Handle for the "HAS_NEW_COVERAGE" tag

    float avgExecTime; ///< The average execution time (for all test cases that have been evaluated)
    float maxExecTime; ///< The maximum exection time (for all test cases that have been evaluated)
    float avgTestCaseSize; ///< The average size (for all test cases that have been evaluated)
    float maxTestCaseSize; ///< The maximum size (for all test cases that have been evaluated)
    float sizeFitnessWeight; ///< A configurable weight to apply to the size factor in computing fitness. Must be >=0.0
    float speedFitnessWeight; ///< A configurable weight to apply to the size factor in computing fitness. Must be >=0.0
    int numTestCases; ///< The total number of test cases that have been evaluated

    bool useCustomWeights; ///< Whether or not custom weights are enabled
};
}
