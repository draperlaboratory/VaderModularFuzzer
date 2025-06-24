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
#include "ComputeDiffStats.hpp"
#include "StorageRegistry.hpp"
#include "plog/Log.h"

using namespace vmf;

#include "ModuleFactory.hpp"
REGISTER_MODULE(ComputeDiffStats);

Module* ComputeDiffStats::build(std::string name)
{
    return new ComputeDiffStats(name);
}

void ComputeDiffStats::init(ConfigInterface& config)
{
    outputRate = config.getIntParam(getModuleName(),"statsRateInSeconds", 1);

    executors = ExecutorModule::getExecutorSubmodules(
        config, config.getSuperModule(getModuleName())->getModuleName());
    for(auto const& e : executors)
    {
        executorNames.emplace_back(e->getModuleName());
    }

    executorAllTestCases.resize(executors.size());
    executorAllCrashes.resize(executors.size());
    executorAllHangs.resize(executors.size());
    executorAllDiffs.resize(executors.size());

    executorUQTestCases.resize(executors.size());
    executorUQCrashes.resize(executors.size());
    executorUQHangs.resize(executors.size());
    executorUQDiffs.resize(executors.size());

    executorAverageCPs.resize(executors.size());
    executorLatestCPs.resize(executors.size());
    executorPrevTCTotal.resize(executors.size());
    executorLastFindTS.resize(executors.size());
    executorStaleDuration.resize(executors.size());
}


ComputeDiffStats::ComputeDiffStats(std::string name) :
    OutputModule(name)
{
    // Output rate variables
    outputRate = 0;
    timeLastComputedStats = time(0);
    
    // Statistics varaibles
    executorAllTestCases = {}; // vector variables will have to be re-sized during init
    executorAllCrashes = {};
    executorAllHangs = {};
    executorAllDiffs = {};

    executorUQTestCases = {};
    executorUQCrashes = {};
    executorUQHangs = {};
    executorUQDiffs = {};
    
    total_time = 0;
    executorAverageCPs = {};
    executorLatestCPs = {};
    executorPrevTCTotal = {};

    executorLastFindTS = {};
    executorStaleDuration = {};

    // Storage(-related) Tags
    hungTag = 0;
    crashedTag = 0;
    deviantTag = 0;
    executorNames = {};
    executorTagIDs = {};
    
    // Single Output Keys
    grandUQTotalMetadataKey = 0;
    grandUQCrashedMetadataKey = 0;
    grandUQHungMetadataKey = 0;
    grandUQDiffMetadataKey = 0;

    grandTotalMetadataKey = 0;
    grandCrashedMetadataKey = 0;
    grandHungMetadataKey = 0;
    grandDiffMetadataKey = 0;

    // Per-executor Keylists
    executorAllTCMetadataKeys = {};
    executorAllCrashMetadataKeys = {};
    executorAllHungMetadataKeys = {};
    executorAllDiffMetadataKeys = {};

    executorUQTCMetadataKeys = {};
    executorUQCrashMetadataKeys = {};
    executorUQHungMetadataKeys = {};
    executorUQDiffMetadataKeys = {};

    executorAverageEPSMetadataKeys = {};
    executorLatestEPSMetadataKeys = {};
    executorStaleDurationMetadataKeys = {};
}

ComputeDiffStats::~ComputeDiffStats()
{

}

void ComputeDiffStats::registerStorageNeeds(StorageRegistry& registry)
{
    crashedTag = registry.registerTag("CRASHED", StorageRegistry::READ_ONLY);
    hungTag = registry.registerTag("HUNG", StorageRegistry::READ_ONLY);
    deviantTag = registry.registerTag("DEVIATED", StorageRegistry::READ_ONLY);

    // input executor data tag keys
    for(std::string& e : executorNames)
    {
        executorTagIDs.emplace_back(registry.registerTag(e, StorageRegistry::READ_ONLY));
    }
}

void ComputeDiffStats::registerMetadataNeeds(StorageRegistry& registry)
{
    // Single Output Keys
    grandUQTotalMetadataKey     = registry.registerKey("GRAND_UQ_TEST_CASES", StorageRegistry::UINT, StorageRegistry::WRITE_ONLY);
    grandUQCrashedMetadataKey   = registry.registerKey("GRAND_UQ_CRASHED_CASES", StorageRegistry::UINT, StorageRegistry::WRITE_ONLY);
    grandUQHungMetadataKey      = registry.registerKey("GRAND_UQ_HUNG_CASES", StorageRegistry::UINT, StorageRegistry::WRITE_ONLY);
    grandUQDiffMetadataKey      = registry.registerKey("GRAND_UQ_DIFF_CASES", StorageRegistry::UINT, StorageRegistry::WRITE_ONLY);
    
    grandTotalMetadataKey       = registry.registerKey("GRAND_TEST_CASES", StorageRegistry::U64, StorageRegistry::WRITE_ONLY);
    grandCrashedMetadataKey     = registry.registerKey("GRAND_CRASHED_CASES", StorageRegistry::UINT, StorageRegistry::WRITE_ONLY);
    grandHungMetadataKey        = registry.registerKey("GRAND_HUNG_CASES", StorageRegistry::UINT, StorageRegistry::WRITE_ONLY);
    grandDiffMetadataKey        = registry.registerKey("GRAND_DIFF_CASES", StorageRegistry::UINT, StorageRegistry::WRITE_ONLY);

    // Per-executor Output KeyLists
    for(std::string& e : executorNames)
    {
        executorAllTCMetadataKeys.emplace_back(registry.registerKey(
            "TOTAL_TEST_CASES_" + e, StorageRegistry::U64, StorageRegistry::WRITE_ONLY));
        executorAllCrashMetadataKeys.emplace_back(registry.registerKey(
            "TOTAL_CRASHED_CASES_" + e, StorageRegistry::UINT, StorageRegistry::WRITE_ONLY));
        executorAllHungMetadataKeys.emplace_back(registry.registerKey(
            "TOTAL_HUNG_CASES_" + e, StorageRegistry::UINT, StorageRegistry::WRITE_ONLY));
        executorAllDiffMetadataKeys.emplace_back(registry.registerKey(
            "TOTAL_DIFF_CASES_" + e, StorageRegistry::UINT, StorageRegistry::WRITE_ONLY));    

        executorUQTCMetadataKeys.emplace_back(registry.registerKey(
            "UQ_TEST_CASES_" + e, StorageRegistry::UINT, StorageRegistry::WRITE_ONLY));
        executorUQCrashMetadataKeys.emplace_back(registry.registerKey(
            "UQ_CRASHED_CASES_" + e, StorageRegistry::UINT, StorageRegistry::WRITE_ONLY));
        executorUQHungMetadataKeys.emplace_back(registry.registerKey(
            "UQ_HUNG_CASES_" + e, StorageRegistry::UINT, StorageRegistry::WRITE_ONLY));
        executorUQDiffMetadataKeys.emplace_back(registry.registerKey(
            "UQ_DIFF_CASES_" + e, StorageRegistry::UINT, StorageRegistry::WRITE_ONLY));

        executorAverageEPSMetadataKeys.emplace_back(registry.registerKey(
            "AVERAGE_EPS_" + e, StorageRegistry::FLOAT, StorageRegistry::WRITE_ONLY));
        executorLatestEPSMetadataKeys.emplace_back(registry.registerKey(
            "LATEST_EPS_" + e, StorageRegistry::FLOAT, StorageRegistry::WRITE_ONLY));
        executorStaleDurationMetadataKeys.emplace_back(registry.registerKey(
            "DUR_LAST_FIND_" + e, StorageRegistry::FLOAT, StorageRegistry::WRITE_ONLY));
    }
}


void ComputeDiffStats::run(StorageModule& storage)
{
    StorageEntry& metadata = storage.getMetadata();

    //These statistics have to be counted on every pass through the fuzzing loop
    //because they require examining the newEntries (which change each time)
    unsigned long long grandTotalTests = 0;
    unsigned int grandTotalCrashes = 0;
    unsigned int grandTotalHangs = 0;
    unsigned int grandTotalDeviants = 0;

    for(size_t i=0; i<executorTagIDs.size(); i++)
    {
        executorAllTestCases[i] += storage.getNewEntriesByTag(executorTagIDs[i])->getSize();
        executorAllCrashes[i]   += storage.getNewEntriesByIntersection(executorTagIDs[i], crashedTag)->getSize();
        executorAllHangs[i]     += storage.getNewEntriesByIntersection(executorTagIDs[i], hungTag)->getSize();
        executorAllDiffs[i]     += storage.getNewEntriesByIntersection(executorTagIDs[i], deviantTag)->getSize();

        metadata.setValue(executorAllTCMetadataKeys[i], executorAllTestCases[i]);
        metadata.setValue(executorAllCrashMetadataKeys[i], executorAllCrashes[i]);
        metadata.setValue(executorAllHungMetadataKeys[i], executorAllHangs[i]);
        metadata.setValue(executorAllDiffMetadataKeys[i], executorAllDiffs[i]);

        grandTotalTests     += executorAllTestCases[i];
        grandTotalCrashes   += executorAllCrashes[i];
        grandTotalHangs     += executorAllHangs[i];
        grandTotalDeviants  += executorAllDiffs[i];
    }   
    metadata.setValue(grandTotalMetadataKey, grandTotalTests);
    metadata.setValue(grandCrashedMetadataKey, grandTotalCrashes);
    metadata.setValue(grandHungMetadataKey, grandTotalHangs);
    metadata.setValue(grandDiffMetadataKey, grandTotalDeviants);

    //These statistics are computed at the configured rate
    time_t now = time(0);
    double elapsed = difftime(now, timeLastComputedStats);
    if(elapsed > outputRate)
    {
        timeLastComputedStats = now;
        total_time += elapsed;
        // Reset the grandTotalUQ fields to be re-totaled later 
        unsigned int grandUQTotalTests = 0;
        unsigned int grandUQTotalCrashes = 0;
        unsigned int grandUQTotalHangs = 0;
        unsigned int grandUQTotalDiffs = 0;

        // Compute unique statistics by executors
        unsigned int newUniqueTotal = 0;
        for(size_t i=0; i<executorTagIDs.size(); i++)
        {
            // SUT TIME SINCE LAST FINDING per executor:
            newUniqueTotal = storage.getSavedEntriesByTag(executorTagIDs[i])->getSize();
            now = time(0);
            if(newUniqueTotal <= executorUQTestCases[i])
            {
                // Nothing new; update how long we've waited for this executor to find someting new
                executorStaleDuration[i] = (float)difftime(now, executorLastFindTS[i]);
            }
            else
            {
                // Found something new; reset StaleDuration and set LastFindTS
                executorLastFindTS[i] = now;
                executorStaleDuration[i] = 0.0;
            }
            // TOTAL UQ for CASES, CRASHES, and HANGS per executor:
            executorUQTestCases[i] = newUniqueTotal;
            executorUQCrashes[i] = storage.getSavedEntriesByIntersection(crashedTag, executorTagIDs[i])->getSize();
            executorUQHangs[i] = storage.getSavedEntriesByIntersection(hungTag, executorTagIDs[i])->getSize();
            executorUQDiffs[i] = storage.getSavedEntriesByIntersection(deviantTag, executorTagIDs[i])->getSize();

            // GRAND TOTAL UQ for CASES, CRASHES, and HANGS
            grandUQTotalTests   += executorUQTestCases[i];
            grandUQTotalCrashes += executorUQCrashes[i];
            grandUQTotalHangs   += executorUQHangs[i];
            grandUQTotalDiffs   += executorUQDiffs[i];

            // SUT EXEC/SEC per executor:
            executorAverageCPs[i] = static_cast<float>(executorAllTestCases[i] / total_time);
            executorLatestCPs[i] = static_cast<float>(
                (executorAllTestCases[i] - executorPrevTCTotal[i]) / elapsed);
            executorPrevTCTotal[i] = executorAllTestCases[i];

            // Write Unique cases for this executor to metadata
            metadata.setValue(executorUQTCMetadataKeys[i], executorUQTestCases[i]);
            metadata.setValue(executorUQCrashMetadataKeys[i], executorUQCrashes[i]);            
            metadata.setValue(executorUQHungMetadataKeys[i], executorUQHangs[i]);            
            metadata.setValue(executorUQDiffMetadataKeys[i], executorUQDiffs[i]);

            // Write Timing data for this executor to metadata
            metadata.setValue(executorLatestEPSMetadataKeys[i], executorLatestCPs[i]);            
            metadata.setValue(executorAverageEPSMetadataKeys[i], executorAverageCPs[i]);
            metadata.setValue(executorStaleDurationMetadataKeys[i], executorStaleDuration[i]);            
        }

        // Write Grand Total number of Unique cases to metadata
        metadata.setValue(grandUQTotalMetadataKey, grandUQTotalTests);
        metadata.setValue(grandUQCrashedMetadataKey, grandUQTotalCrashes);
        metadata.setValue(grandUQHungMetadataKey, grandUQTotalHangs);
        metadata.setValue(grandUQDiffMetadataKey, grandUQTotalDiffs);
    }
}