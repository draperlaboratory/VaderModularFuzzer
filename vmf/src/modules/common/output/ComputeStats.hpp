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

namespace vmf
{
/**
 * @brief OutputModule that computes execution statistics and publishes them
 * to metadata.
 * A number of fields are written, for usage by other modules (such as StatsOutput).
 * @image html CoreModuleDataModel_6.png width=800px
 * @image latex CoreModuleDataModel_6.png width=6in
 */
class ComputeStats : public OutputModule {
public:
    static Module* build(std::string name);
    virtual void init(ConfigInterface& config);

    virtual void registerStorageNeeds(StorageRegistry& registry);
    virtual void registerMetadataNeeds(StorageRegistry& registry);

    virtual void run(StorageModule& storage);

    ComputeStats(std::string name);
    virtual ~ComputeStats();
private:

    //These are the statistics collected/computed
    ///Total Fuzzer executions
    unsigned long long currentTotal;
    //Total Fuzzer crashes
    unsigned int totalCrashes;
    //Total Fuzzer hangs
    unsigned int totalHangs;
    ///Total unique/interesting test cases
    unsigned int uniqueTotal; 
    ///Total number of crashes that are unique
    unsigned int uniqueCrashes;
    ///Total number of hangs that are unique
    unsigned int uniqueHangs; 
    ///Time since last interesting test case was found (in seconds)
    float timeSinceLastFound;
    /// Average executions per second
    float casePerSec;
    /// Recent executions per second (since last call to output module)
    float latestCasePerSec;

    int outputRate;
    time_t timeLastComputedStats;
    time_t timeLastInterestingTestCaseFound;
    unsigned long long prevTestCaseTotal;
    double total_time;

    //storage handles
    int hungTag;
    int crashedTag;
    int totalTCMetadataKey;
    int crashedTotalMetadata;
    int hungTotalMetadata;
    int uniqueTCMetadataKey;
    int uniqueCrashedMetadataKey;
    int uniqueHungMetadataKey;
    int latestExecPerSecMetadataKey;
    int averageExecPerSecMetadataKey;
    int secondsSinceLastUniqueMetadataKey;

};
}