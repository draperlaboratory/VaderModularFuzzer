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
#include "ComputeStats.hpp"

using namespace vmf;

#include "ModuleFactory.hpp"
REGISTER_MODULE(ComputeStats);

/**
 * @brief Builder method to support the ModuleFactory
 * Constructs an instance of this class
 * @return Module* 
 */
Module* ComputeStats::build(std::string name)
{
    return new ComputeStats(name);
}

/**
 * @brief Initialization method
 * Reads in all configuration options for this class
 * 
 * @param config 
 */
void ComputeStats::init(ConfigInterface& config)
{
    outputRate = config.getIntParam(getModuleName(),"statsRateInSeconds", 1);
    timeLastComputedStats = time(0);
    timeLastInterestingTestCaseFound = time(0);
    prevTestCaseTotal = 0;
    total_time = 0;
    uniqueTotal = 0;
    currentTotal = 0;
    totalCrashes = 0;
    totalHangs = 0;
}

/**
 * @brief Construct a new Stats Outputobject
 * 
 * @param name the name of the module
 */
ComputeStats::ComputeStats(std::string name) :
    OutputModule(name)
{
    outputRate = 0;
}

ComputeStats::~ComputeStats()
{

}

void ComputeStats::registerStorageNeeds(StorageRegistry& registry)
{
    crashedTag = registry.registerTag("CRASHED", StorageRegistry::READ_ONLY);
    hungTag = registry.registerTag("HUNG", StorageRegistry::READ_ONLY);
}

void ComputeStats::registerMetadataNeeds(StorageRegistry& registry)
{
    //outputs
    totalTCMetadataKey = registry.registerKey("TOTAL_TEST_CASES", StorageRegistry::UINT, StorageRegistry::WRITE_ONLY);
    crashedTotalMetadata = registry.registerKey("TOTAL_CRASHED_CASES", StorageRegistry::UINT, StorageRegistry::WRITE_ONLY);
    hungTotalMetadata = registry.registerKey("TOTAL_HUNG_CASES", StorageRegistry::UINT, StorageRegistry::WRITE_ONLY);
    uniqueTCMetadataKey = registry.registerKey("UNIQUE_TEST_CASES", StorageRegistry::UINT, StorageRegistry::WRITE_ONLY);
    uniqueCrashedMetadataKey = registry.registerKey("UNIQUE_CRASHED_CASES", StorageRegistry::UINT, StorageRegistry::WRITE_ONLY);
    uniqueHungMetadataKey = registry.registerKey("UNIQUE_HUNG_CASES", StorageRegistry::UINT, StorageRegistry::WRITE_ONLY);
    latestExecPerSecMetadataKey = registry.registerKey("LATEST_EXEC_PER_SEC", StorageRegistry::FLOAT, StorageRegistry::WRITE_ONLY);
    averageExecPerSecMetadataKey = registry.registerKey("AVERAGE_EXEC_PER_SEC", StorageRegistry::FLOAT, StorageRegistry::WRITE_ONLY);
    secondsSinceLastUniqueMetadataKey = registry.registerKey("SECONDS_SINCE_LAST_UNIQUE_FINDING", StorageRegistry::FLOAT, StorageRegistry::WRITE_ONLY);
}


void ComputeStats::run(StorageModule& storage)
{
    StorageEntry& metadata = storage.getMetadata();

    //These statistics have to be counted on every pass through the fuzzing loop
    //because they require examining the newEntries (which change each time)

    //Examine storage to update total counts
    currentTotal = currentTotal + storage.getNewEntries()->getSize();
    totalCrashes = totalCrashes + storage.getNewEntriesByTag(crashedTag)->getSize();
    totalHangs = totalHangs + storage.getNewEntriesByTag(hungTag)->getSize();

    metadata.setValue(totalTCMetadataKey,currentTotal);
    metadata.setValue(crashedTotalMetadata,totalCrashes);
    metadata.setValue(hungTotalMetadata,totalHangs);

    //These statistics are computed at the configured rate
    time_t now = time(0);
    double elapsed = difftime(now, timeLastComputedStats);
    if(elapsed > outputRate)
    {
        timeLastComputedStats = now;

        //Get the number of unique test cases by looking at what is in storage currently
        unsigned int newUniqueTotal = storage.getSavedEntries()->getSize();
        time_t now = time(0);
        if(newUniqueTotal <= uniqueTotal)
        {
            //Nothing new was found -- Compute how long it's been since the last new finding
            timeSinceLastFound = (float)difftime(now, timeLastInterestingTestCaseFound);
        }
        else
        {
            //We found something new, store the timestamp and set the time diff to 0.0
            timeLastInterestingTestCaseFound = now;
            timeSinceLastFound = 0.0;
        }
        uniqueTotal = newUniqueTotal;
        uniqueCrashes = storage.getSavedEntriesByTag(crashedTag)->getSize();
        uniqueHangs = storage.getSavedEntriesByTag(hungTag)->getSize();

        //Exec/s must be computed 
        total_time += elapsed;
        casePerSec = currentTotal / total_time;
        latestCasePerSec = (currentTotal - prevTestCaseTotal)/elapsed;
        prevTestCaseTotal = currentTotal;

        //Finally, write the data to metadata
        metadata.setValue(uniqueTCMetadataKey,uniqueTotal);
        metadata.setValue(uniqueCrashedMetadataKey,uniqueCrashes);
        metadata.setValue(uniqueHungMetadataKey,uniqueHangs);
        
        metadata.setValue(latestExecPerSecMetadataKey,latestCasePerSec);
        metadata.setValue(averageExecPerSecMetadataKey,casePerSec);

        metadata.setValue(secondsSinceLastUniqueMetadataKey,timeSinceLastFound);
    }
}




