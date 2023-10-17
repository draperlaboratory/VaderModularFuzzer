/* =============================================================================
 * Vader Modular Fuzzer (VMF)
 * Copyright (c) 2021-2023 The Charles Stark Draper Laboratory, Inc.
 * <vader@draper.com>
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
#pragma once


#include "FeedbackModule.hpp"
#include "AFLExecutor.hpp"

namespace vader
{

/**
 * @brief Feedback module to examine results from AFLForkserverExecutor
 *
 */
class AFLFeedback : public FeedbackModule {
public:

    static Module* build(std::string name);
    virtual void init(ConfigInterface& config);

    virtual void registerStorageNeeds(StorageRegistry& registry);
    virtual void registerMetadataNeeds(StorageRegistry& registry);
    virtual void setExecutor(ExecutorModule* executor);
    virtual bool evaluateTestCaseResults(StorageModule& storage, StorageEntry* e); 

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
protected:

    int testCaseKey; ///< Handle for the "TEST_CASE" field
    int fitnessKey; ///< Handle for the "FITNESS" field
    int normalTag; ///< Handle for the "RAN_SUCCESSFULLY" field
    int crashedTag; ///< Handle for the "CRASHED" tag
    int hungTag; ///< Handle for the "HUNG" tag
    int crashedTotalMetadata; ///< Handle for the "TOTAL_CRASHED_CASES" metadata field
    int hungTotalMetadata; ///< Handle for the "TOTAL_HUNG_CASES" metadata field
    int bytesCoveredMetadata; ///< Handle for the "TOTAL_BYTES_COVERED" metadata field
    int mapSizeMetadata; ///< Handle for the "MAP_SIZE" metadata field
    AFLExecutor* executor; ///< Pointer to the AFLExecutor that has been set for this object

    float avgExecTime; ///< The average execution time (for all test cases that have been evaluated)
    float maxExecTime; ///< The maximum exection time (for all test cases that have been evaluated)
    float avgTestCaseSize; ///< The average size (for all test cases that have been evaluated)
    float maxTestCaseSize; ///< The maximum size (for all test cases that have been evaluated)
    float sizeFitnessWeight; ///< A configurable weight to apply to the size factor in computing fitness. Must be >=0.0
    float speedFitnessWeight; ///< A configurable weight to apply to the size factor in computing fitness. Must be >=0.0
    int numTestCases; ///< The total number of test cases that have been evaluated
    int mapSize; ///< The map size

    bool useCustomWeights; ///< Whether or not custom weights are enabled
};
}
