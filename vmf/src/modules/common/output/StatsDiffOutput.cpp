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
#include <iomanip>
#include <sstream>
#include <cmath>
#include "StatsDiffOutput.hpp"
#include "Logging.hpp"
#include "ExecutorModule.hpp"

using namespace vmf;
#define MAGIC_SPACE 6

#include "ModuleFactory.hpp"
REGISTER_MODULE(StatsDiffOutput);

/**
 * @brief Builder method to support the ModuleFactory
 * Constructs an instance of this class
 * @return Module* 
 */
Module* StatsDiffOutput::build(std::string name)
{
    return new StatsDiffOutput(name);
}

/**
 * @brief Initialization method
 * Reads in all configuration options for this class
 * 
 * @param config 
 */
void StatsDiffOutput::init(ConfigInterface& config)
{
    int defaultRate = 5;
    outputRate = config.getIntParam(getModuleName(),"outputRateInSeconds", defaultRate);

    for(auto const& e : ExecutorModule::getExecutorSubmodules(
        config, config.getSuperModule(getModuleName())->getModuleName()))
    {
        executorNames.emplace_back(e->getModuleName());
    }
}

/**
 * @brief Construct a new Differential Statics Outputobject
 * 
 * @param name the name of the module
 */
StatsDiffOutput::StatsDiffOutput(std::string name) :
    OutputModule(name)
{
    outputRate = 0;
    format_rspace = 6;
    executorNames = {};

    // single metadata keys
    grandUQTotalMetadataKey     = 0;
    grandUQCrashedMetadataKey   = 0;
    grandUQHungMetadataKey      = 0;
    grandUQDiffMetadataKey      = 0;

    grandTotalMetadataKey   = 0;
    grandCrashedMetadataKey = 0;
    grandHungMetadataKey    = 0;
    grandDiffMetadataKey    = 0;

    // per-executor metadata key
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

StatsDiffOutput::~StatsDiffOutput()
{

}

void StatsDiffOutput::registerStorageNeeds(StorageRegistry& registry)
{
    // NO TAGS NEEDED
}

void StatsDiffOutput::registerMetadataNeeds(StorageRegistry& registry)
{
    // Single Output Keys
    grandUQTotalMetadataKey     = registry.registerKey("GRAND_UQ_TEST_CASES", StorageRegistry::UINT, StorageRegistry::READ_ONLY);
    grandUQCrashedMetadataKey   = registry.registerKey("GRAND_UQ_CRASHED_CASES", StorageRegistry::UINT, StorageRegistry::READ_ONLY);
    grandUQHungMetadataKey      = registry.registerKey("GRAND_UQ_HUNG_CASES", StorageRegistry::UINT, StorageRegistry::READ_ONLY);
    grandUQDiffMetadataKey      = registry.registerKey("GRAND_UQ_DIFF_CASES", StorageRegistry::UINT, StorageRegistry::READ_ONLY);
    
    grandTotalMetadataKey       = registry.registerKey("GRAND_TEST_CASES", StorageRegistry::U64, StorageRegistry::READ_ONLY);
    grandCrashedMetadataKey     = registry.registerKey("GRAND_CRASHED_CASES", StorageRegistry::UINT, StorageRegistry::READ_ONLY);
    grandHungMetadataKey        = registry.registerKey("GRAND_HUNG_CASES", StorageRegistry::UINT, StorageRegistry::READ_ONLY);
    grandDiffMetadataKey        = registry.registerKey("GRAND_DIFF_CASES", StorageRegistry::UINT, StorageRegistry::READ_ONLY);

    // Per-executor Output KeyLists
    for(std::string& e : executorNames)
    {
        executorAllTCMetadataKeys.emplace_back(registry.registerKey(
            "TOTAL_TEST_CASES_" + e, StorageRegistry::U64, StorageRegistry::READ_ONLY));
        executorAllCrashMetadataKeys.emplace_back(registry.registerKey(
            "TOTAL_CRASHED_CASES_" + e, StorageRegistry::UINT, StorageRegistry::READ_ONLY));
        executorAllHungMetadataKeys.emplace_back(registry.registerKey(
            "TOTAL_HUNG_CASES_" + e, StorageRegistry::UINT, StorageRegistry::READ_ONLY));
        executorAllDiffMetadataKeys.emplace_back(registry.registerKey(
            "TOTAL_DIFF_CASES_" + e, StorageRegistry::UINT, StorageRegistry::READ_ONLY));

        executorUQTCMetadataKeys.emplace_back(registry.registerKey(
            "UQ_TEST_CASES_" + e, StorageRegistry::UINT, StorageRegistry::READ_ONLY));
        executorUQCrashMetadataKeys.emplace_back(registry.registerKey(
            "UQ_CRASHED_CASES_" + e, StorageRegistry::UINT, StorageRegistry::READ_ONLY));
        executorUQHungMetadataKeys.emplace_back(registry.registerKey(
            "UQ_HUNG_CASES_" + e, StorageRegistry::UINT, StorageRegistry::READ_ONLY));
        executorUQDiffMetadataKeys.emplace_back(registry.registerKey(
            "UQ_DIFF_CASES_" + e, StorageRegistry::UINT, StorageRegistry::READ_ONLY));

        executorAverageEPSMetadataKeys.emplace_back(registry.registerKey(
            "AVERAGE_EPS_" + e, StorageRegistry::FLOAT, StorageRegistry::READ_ONLY));
        executorLatestEPSMetadataKeys.emplace_back(registry.registerKey(
            "LATEST_EPS_" + e, StorageRegistry::FLOAT, StorageRegistry::READ_ONLY));
        executorStaleDurationMetadataKeys.emplace_back(registry.registerKey(
            "DUR_LAST_FIND_" + e, StorageRegistry::FLOAT, StorageRegistry::READ_ONLY));
    }
}

OutputModule::ScheduleTypeEnum StatsDiffOutput::getDesiredScheduleType()
{
    return OutputModule::CALL_ON_NUM_SECONDS;
}

int StatsDiffOutput::getDesiredScheduleRate()
{
    return outputRate;
}

void StatsDiffOutput::run(StorageModule& storage)
{
    StorageEntry& metadata = storage.getMetadata();
    
    // Get Statistics from metadata
    unsigned long long grandTotalTests = metadata.getU64Value(grandTotalMetadataKey);
    unsigned int grandTotalCrashes = metadata.getUIntValue(grandCrashedMetadataKey);
    unsigned int grandTotalHangs = metadata.getUIntValue(grandHungMetadataKey);
    unsigned int grandTotalDiffs = metadata.getUIntValue(grandDiffMetadataKey);

    unsigned int grandUQTotalTests = metadata.getUIntValue(grandUQTotalMetadataKey);
    unsigned int grandUQTotalCrashes = metadata.getUIntValue(grandUQCrashedMetadataKey);
    unsigned int grandUQTotalHangs = metadata.getUIntValue(grandUQHungMetadataKey);
    unsigned int grandUQTotalDiffs = metadata.getUIntValue(grandUQDiffMetadataKey);

    std::vector<unsigned long long>executorAllTestCases = {};
    std::vector<unsigned int>executorAllCrashes = {};
    std::vector<unsigned int>executorAllHangs = {};
    std::vector<unsigned int>executorAllDiffs = {};

    std::vector<unsigned int>executorUQTestCases = {};
    std::vector<unsigned int>executorUQCrashes = {};
    std::vector<unsigned int>executorUQHangs = {};
    std::vector<unsigned int>executorUQDiffs = {};

    std::vector<float>executorAverageCPs = {};
    std::vector<float>executorLatestCPs = {};
    std::vector<float>executorStaleDuration = {};

    for(size_t i=0; i<executorNames.size(); i++)
    {
        executorAllTestCases.emplace_back(metadata.getU64Value(executorAllTCMetadataKeys[i]));
        executorAllCrashes.emplace_back(metadata.getUIntValue(executorAllCrashMetadataKeys[i]));
        executorAllHangs.emplace_back(metadata.getUIntValue(executorAllHungMetadataKeys[i]));
        executorAllDiffs.emplace_back(metadata.getUIntValue(executorAllDiffMetadataKeys[i]));

        executorUQTestCases.emplace_back(metadata.getUIntValue(executorUQTCMetadataKeys[i]));
        executorUQCrashes.emplace_back(metadata.getUIntValue(executorUQCrashMetadataKeys[i]));
        executorUQHangs.emplace_back(metadata.getUIntValue(executorUQHungMetadataKeys[i]));
        executorUQDiffs.emplace_back(metadata.getUIntValue(executorUQDiffMetadataKeys[i]));
        
        executorAverageCPs.emplace_back(metadata.getFloatValue(executorAverageEPSMetadataKeys[i]));
        executorLatestCPs.emplace_back(metadata.getFloatValue(executorLatestEPSMetadataKeys[i]));
        executorStaleDuration.emplace_back(metadata.getFloatValue(executorStaleDurationMetadataKeys[i]));
    }

    //Output the data
    int h_len = 31; // number of characters in longest header
    // Calculate the number of digits for the # of tests we've run
    unsigned int num_digits = grandTotalTests > 0 ? static_cast<int>( std::log10(grandTotalTests) ) + 1 : 1;
    format_rspace = num_digits > format_rspace ? num_digits : format_rspace; 

    ogl(h_len, format_rspace, grandUQTotalTests, grandTotalTests, "TEST CASES");
    odl(h_len, executorUQTestCases, executorAllTestCases, " TOTAL");

    ogl(h_len, format_rspace, grandUQTotalCrashes, grandTotalCrashes, "CRASHES");
    odl(h_len, executorUQCrashes, executorAllCrashes, " TOTAL");

    ogl(h_len, format_rspace, grandUQTotalHangs, grandTotalHangs, "HANGS");
    odl(h_len, executorUQHangs, executorAllHangs, " TOTAL");

    ogl(h_len, format_rspace, grandUQTotalDiffs, grandTotalDiffs, "DEVIANTS");
    odl(h_len, executorUQDiffs, executorAllDiffs, " TOTAL");
    
    LOG_INFO << std::setw(h_len) << std::right << "SUT EXEC/SEC: ";
    for(size_t i=0; i<executorNames.size(); i++)
    {
        LOG_INFO << std::setw(h_len) << std::right << executorNames[i] + ": "
            << std::setw(MAGIC_SPACE-2) << std::left << std::fixed << std::setprecision(0) << executorLatestCPs[i] << "/s"
            << " | " 
            << std::setw(format_rspace-2) << std::left << std::fixed << std::setprecision(0) << executorAverageCPs[i] << "/s AVERAGE";
    }

    LOG_INFO << std::setw(h_len) << std::right << "SUT TIME SINCE LAST FINDING: ";
    for(size_t i=0; i<executorNames.size(); i++)
    {
        LOG_INFO << std::setw(h_len) << std::right << executorNames[i] + ": "
            << executorStaleDuration[i] << "s";
    }

    LOG_INFO << 'o' << std::string(52, '-') << 'o';
}

template <typename T, typename V> // outputDiffLine is shortened to ODL to save on h-space in logging
void StatsDiffOutput::odl(int l_width, std::vector<T> dataCenter, std::vector<V> dataRight, std::string postfix)
{
    for(size_t i=0; i<executorNames.size(); i++)
    {
        LOG_INFO << std::setw(l_width) << std::right << executorNames[i] + ": "
            << std::setw(MAGIC_SPACE) << std::left << dataCenter[i]
            << " | " 
            << std::setw(format_rspace) << dataRight[i]
            << postfix;
    }
}

template<typename T, typename V> // outputGrandLine
void StatsDiffOutput::ogl(int l_width, int r_width, T uqData, V allData, std::string statName)
{
    LOG_INFO << std::setw(l_width) << std::right << "GRAND TOTAL UNIQUE " + statName + ": "
        << std::setw(MAGIC_SPACE) << std::left << uqData 
        << " | " 
        << std::setw(r_width) << std::left<< allData << " TOTAL";
}
