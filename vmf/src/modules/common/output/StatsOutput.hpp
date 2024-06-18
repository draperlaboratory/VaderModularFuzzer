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
 * @brief Output module to provide high level execution statistics to the operator
 * These can be provided to the logger or for distributed fuzzing, to the server,
 * depending on the configuration options selected.  The default behavior is to
 * write to the logger.
 */
class StatsOutput : public OutputModule {
public:
    static Module* build(std::string name);
    virtual void init(ConfigInterface& config);

    virtual void registerStorageNeeds(StorageRegistry& registry);
    virtual void registerMetadataNeeds(StorageRegistry& registry);
    virtual OutputModule::ScheduleTypeEnum getDesiredScheduleType();
    virtual int getDesiredScheduleRate();

    virtual void run(StorageModule& storage);

    StatsOutput(std::string name);
    virtual ~StatsOutput();
private:

    void outputStatistics();

    //These are the statistics collected/computed
    ///Total Fuzzer executions
    int currentTotal;
    ///Total unique/interesting test cases
    int uniqueTotal; 
    ///Total number of detected test cases that crash
    int crashes; 
    ///Total number of crashes that are unique
    int uniqueCrashes;
    ///Total number of detected test cases that hang
    int hangs; 
    ///Total number of hangs that are unique
    int uniqueHangs; 
    ///Total coverage bytes
    int bytesCovered; 
    ///Total coverage map size
    int mapSize;
    ///Time since last interesting test case was found (in seconds)
    float timeSinceLastFound;
    ///Percentage of the coverage map that is being filled
    float mapPercentFull; 
    /// Average executions per second
    float casePerSec;
    /// Recent executions per second (since last call to output module)
    float latestCasePerSec;

    // When true, stats are sent to the server, when false, they are send to the logger instead
    bool writeToServer;
    int outputRate;
    void computeExecutionsPerSecond(int totalTestCaseCount);
    int totalTCCountMetadataKey;
    int totalCrashedCountMetadataKey;
    int totalHungCountMetadataKey;
    int totalBytesCoveredMetadataKey;
    int mapSizeMetadataKey;  

    int crashedTag;
    int hungTag;

    time_t timeLastPrintedStats;
    time_t timeLastInterestingTestCaseFound;
    int prevTestCaseTotal;
    double total_time;
};
}
