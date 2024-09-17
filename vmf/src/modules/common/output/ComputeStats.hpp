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
#pragma once


#include "OutputModule.hpp"

namespace vmf
{
/**
 * @brief Output module that computes execution statistics and publishes them
 * to the metadata.
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
    unsigned int currentTotal;
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
    int prevTestCaseTotal;
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