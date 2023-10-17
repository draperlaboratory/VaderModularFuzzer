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
#include <iomanip>
#include "StatsOutput.hpp"
#include "Logging.hpp"
#include "CDMSClient.hpp"
#include "json11.hpp"

using namespace vader;
using namespace json11;

#include "ModuleFactory.hpp"
REGISTER_MODULE(StatsOutput);

/**
 * @brief Builder method to support the ModuleFactory
 * Constructs an instance of this class
 * @return Module* 
 */
Module* StatsOutput::build(std::string name)
{
    return new StatsOutput(name);
}

/**
 * @brief Initialization method
 * Reads in all configuration options for this class
 * 
 * @param config 
 */
void StatsOutput::init(ConfigInterface& config)
{
    writeToServer = config.getBoolParam(getModuleName(),"sendToServer", false);
    int defaultRate = 5;
    if(writeToServer)
    {
        defaultRate = 20;
    }
    outputRate = config.getIntParam(getModuleName(),"outputRateInSeconds", defaultRate);
    timeLastPrintedStats = time(0);
    timeLastInterestingTestCaseFound = time(0);
    prevTestCaseTotal = 0;
    total_time = 0;
    uniqueTotal = 0;
}

/**
 * @brief Construct a new Stats Outputobject
 * 
 * @param name the name of the module
 */
StatsOutput::StatsOutput(std::string name) :
    OutputModule(name)
{
    outputRate = 0;
}

StatsOutput::~StatsOutput()
{

}

void StatsOutput::registerStorageNeeds(StorageRegistry& registry)
{
    crashedTag = registry.registerTag("CRASHED", StorageRegistry::READ_ONLY);
    hungTag = registry.registerTag("HUNG", StorageRegistry::READ_ONLY);
}

void StatsOutput::registerMetadataNeeds(StorageRegistry& registry)
{
    totalTCCountMetadataKey = registry.registerKey("TOTAL_TEST_CASES", StorageRegistry::INT, StorageRegistry::READ_ONLY);
    totalCrashedCountMetadataKey = registry.registerKey("TOTAL_CRASHED_CASES", StorageRegistry::INT, StorageRegistry::READ_ONLY);
    totalHungCountMetadataKey = registry.registerKey("TOTAL_HUNG_CASES", StorageRegistry::INT, StorageRegistry::READ_ONLY);
    totalBytesCoveredMetadataKey = registry.registerKey("TOTAL_BYTES_COVERED", StorageRegistry::INT, StorageRegistry::READ_ONLY);
    mapSizeMetadataKey = registry.registerKey("MAP_SIZE", StorageRegistry::INT, StorageRegistry::READ_ONLY);        
}

OutputModule::ScheduleTypeEnum StatsOutput::getDesiredScheduleType()
{
    return OutputModule::CALL_ON_NUM_SECONDS;
}

int StatsOutput::getDesiredScheduleRate()
{
    return outputRate;
}

void StatsOutput::run(StorageModule& storage)
{
    StorageEntry& metadata = storage.getMetadata();
    
    //Get basic stats from metadata
    currentTotal = metadata.getIntValue(totalTCCountMetadataKey);
    crashes = metadata.getIntValue(totalCrashedCountMetadataKey);
    hangs = metadata.getIntValue(totalHungCountMetadataKey);
    bytesCovered = metadata.getIntValue(totalBytesCoveredMetadataKey);

    //Get the number of unique test cases by looking at what is in storage currently
    int newUniqueTotal = storage.getEntries()->getSize();
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
    uniqueCrashes = storage.getEntriesByTag(crashedTag)->getSize();
    uniqueHangs = storage.getEntriesByTag(hungTag)->getSize();

    //Compute coverage data
    mapSize = metadata.getIntValue(mapSizeMetadataKey);
    mapPercentFull = (float) 100.0 * bytesCovered / mapSize;

    //Exec/s must be computed (via this helper method)
    computeExecutionsPerSecond(currentTotal);

    //Finally, output the data
    outputStatistics();
}


/**
 * @brief Computes and prints the rate of test case execution
 * 
 * @param totalTestCaseCount the current total number of test cases
 * @param elapsed the elapsed time since the last call to this method
 */
void StatsOutput::computeExecutionsPerSecond(int totalTestCaseCount)
{
    time_t now = time(0);
    double elapsed = difftime(now, timeLastPrintedStats);
    timeLastPrintedStats = now;
    total_time += elapsed;

    casePerSec = totalTestCaseCount / total_time;
    latestCasePerSec = (totalTestCaseCount - prevTestCaseTotal)/elapsed;
    prevTestCaseTotal = totalTestCaseCount;

}

/**
 * @brief Helper method to output the statistics
 * This method either prints to the logger or for distributed fuzzing,
 * sends the output to the server.  This behavior is controlled by the
 * "sendToServer" configuration option.
 */
void StatsOutput::outputStatistics()
{
    if(!writeToServer)
    {
        //Statistics are written to the console
        LOG_INFO << "UNIQUE INTERESTING TEST CASES: " << uniqueTotal;
        LOG_INFO << "UNIQUE CRASHES: " << uniqueCrashes << " (" << crashes << " TOTAL)";
        LOG_INFO << "LATEST EXEC/SEC: " << latestCasePerSec << "/s (" << casePerSec << "/s AVERAGE)";
        LOG_INFO << "TIME SINCE LAST FINDING: " << timeSinceLastFound << " seconds";
        LOG_INFO << "TOTAL EXECUTIONS: " << currentTotal;
        LOG_INFO << "UNIQUE HANGS: " << uniqueHangs << " (" << hangs << " TOTAL)";
        LOG_INFO << "COVERED TUPLES: " << bytesCovered << " / " << mapSize << " (" << \
        std::fixed << std::setprecision(2) << mapPercentFull << "%)";
        LOG_INFO << "---------------------------------";
    }
    else
    {
        //Statistics are send to the CDMS server
        //Note: This webpage had the best documentation of how to 
        //https://stackoverflow.com/questions/38887808/how-to-add-child-nested-element-inside-json-using-json11-library
        Json jsonObj = Json::object 
        {
            {"uid",     CDMSClient::getInstance()->getUniqueId()},
            {"metrics", Json::array 
                {
                Json::object { {"key","uniqueInterestingTestCases"},{"value", uniqueTotal} },
                Json::object { {"key","uniqueCrashes"}, {"value", uniqueCrashes} },
                Json::object { {"key","latestExecPerSec"}, {"value", latestCasePerSec} },
                Json::object { {"key","timeSinceLastFound"}, {"value", timeSinceLastFound} },
                Json::object { {"key","totalExecutions"}, {"value",currentTotal} },  
                Json::object { {"key","totalUniqueHangs"}, {"value", uniqueHangs} },
                Json::object { {"key","avgExecPerSec"}, {"value", casePerSec} },
                Json::object { {"key","totalCrashes"}, {"value",crashes} },
                Json::object { {"key","totalHangs"}, {"value", hangs} },
                Json::object { {"key","coveredTuples"}, {"value", bytesCovered} },
                Json::object { {"key","mapSize"}, {"value", mapSize} },
                Json::object { {"key","mapPercentFull"}, {"value", mapPercentFull} }
                }
            } 
        };

        CDMSClient::getInstance()->sendKPI(jsonObj);
    }
}

