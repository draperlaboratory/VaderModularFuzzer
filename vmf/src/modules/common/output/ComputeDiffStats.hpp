
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


#include "OutputModule.hpp"
#include "ExecutorModule.hpp"

namespace vmf
{
/**
 * @brief OutputModule that computes execution statistics and publishes them
 * to metadata.
 * A number of fields are written, for usage by other modules (such as StatsDiffOutput).
 * @image html CoreModuleDataModel_6.png width=800px
 * @image latex CoreModuleDataModel_6.png width=6in
 */
class ComputeDiffStats : public OutputModule {
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
     * Create copies of essential input tags.
     *
     * @param registry
     */
    virtual void registerStorageNeeds(StorageRegistry& registry);

    /**
     * @brief Register metadata about group and individual fuzzing statistics
     * Register campaign-wide statistics as _Grand_ metadata statistics and per-executor metadata
     * under their respective metadata type and ExecutorName. 
     *
     * @param registry
     */
    virtual void registerMetadataNeeds(StorageRegistry& registry);

    /**
     * @brief Compute rolling statistics about each ExecutorModule and the campaign as a whole
     */
    virtual void run(StorageModule& storage);

    /**
    * @brief Construct a new StatsOutput object for Differential Fuzzing
    * 
    * @param name the name of the module
    */
    ComputeDiffStats(std::string name);
    virtual ~ComputeDiffStats();
private:
    // control variables
    int outputRate; ///< Elapsed time before entire statistics are reset
    time_t timeLastComputedStats; ///< Timestamp for accurate average calculation
    
    // Groupings of statistics variables per executor
    std::vector<unsigned long long>executorAllTestCases;
    std::vector<unsigned int>executorAllCrashes;
    std::vector<unsigned int>executorAllHangs;
    std::vector<unsigned int>executorAllDiffs;

    std::vector<unsigned int>executorUQTestCases;
    std::vector<unsigned int>executorUQCrashes;
    std::vector<unsigned int>executorUQHangs;
    std::vector<unsigned int>executorUQDiffs;

    double total_time; ///< Elapsed time of the campaign
    // Rolling average of...
    std::vector<float>executorAverageCPs; ///< Executions Per Second
    std::vector<float>executorLatestCPs;
    std::vector<unsigned long long>executorPrevTCTotal; ///< Total Testcases
    std::vector<time_t>executorLastFindTS; ///< Time since last finding
    std::vector<float>executorStaleDuration;


    // storage tags
    int hungTag; ///< SUT hung
    int crashedTag; ///< SUT crashed
    int deviantTag; ///< SUTs resulted in differential behavior
    std::vector<int> executorTagIDs; ///< Executor IDs
    // Differential Executor variables for registration + operation
    std::vector<std::string> executorNames;
    std::vector<ExecutorModule*> executors;
    

    // Campaign-wide metadata keys
    int grandUQTotalMetadataKey;
    int grandUQCrashedMetadataKey;
    int grandUQHungMetadataKey;
    int grandUQDiffMetadataKey;

    int grandTotalMetadataKey;
    int grandCrashedMetadataKey;
    int grandHungMetadataKey;
    int grandDiffMetadataKey;

    // Groupings for per-executor metadata keys
    // total (end state)
    std::vector<int> executorAllTCMetadataKeys;
    std::vector<int> executorAllCrashMetadataKeys;
    std::vector<int> executorAllHungMetadataKeys;
    std::vector<int> executorAllDiffMetadataKeys;

    // number of (end state) with new coverage
    std::vector<int> executorUQTCMetadataKeys;
    std::vector<int> executorUQCrashMetadataKeys;
    std::vector<int> executorUQHungMetadataKeys;
    std::vector<int> executorUQDiffMetadataKeys;

    // timing statistics
    std::vector<int> executorAverageEPSMetadataKeys;
    std::vector<int> executorLatestEPSMetadataKeys;
    std::vector<int> executorStaleDurationMetadataKeys;
};
}