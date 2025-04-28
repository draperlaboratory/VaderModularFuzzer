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
#include "StatsOutput.hpp"
#include "Logging.hpp"
#include "CDMSClient.hpp"
#include "json11.hpp"

using namespace vmf;
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

}

void StatsOutput::registerMetadataNeeds(StorageRegistry& registry)
{
    totalTCCountMetadataKey = registry.registerKey("TOTAL_TEST_CASES", StorageRegistry::U64, StorageRegistry::READ_ONLY);
    totalCrashedCountMetadataKey = registry.registerKey("TOTAL_CRASHED_CASES", StorageRegistry::UINT, StorageRegistry::READ_ONLY);
    totalHungCountMetadataKey = registry.registerKey("TOTAL_HUNG_CASES", StorageRegistry::UINT, StorageRegistry::READ_ONLY);
    
    totalBytesCoveredMetadataKey = registry.registerKey("TOTAL_BYTES_COVERED", StorageRegistry::UINT, StorageRegistry::READ_ONLY);
    secondsSinceLastUniqueMetadataKey = registry.registerKey("SECONDS_SINCE_LAST_UNIQUE_FINDING", StorageRegistry::FLOAT, StorageRegistry::READ_ONLY);

    uniqueTCCountMetadataKey = registry.registerKey("UNIQUE_TEST_CASES", StorageRegistry::UINT, StorageRegistry::READ_ONLY);
    uniqueCrashedCountMetadataKey = registry.registerKey("UNIQUE_CRASHED_CASES", StorageRegistry::UINT, StorageRegistry::READ_ONLY);
    uniqueHungCountMetadataKey = registry.registerKey("UNIQUE_HUNG_CASES", StorageRegistry::UINT, StorageRegistry::READ_ONLY);
    
    latestExecPerSecMetadataKey = registry.registerKey("LATEST_EXEC_PER_SEC", StorageRegistry::FLOAT, StorageRegistry::READ_ONLY);
    averageExecPerSecMetadataKey = registry.registerKey("AVERAGE_EXEC_PER_SEC", StorageRegistry::FLOAT, StorageRegistry::READ_ONLY);
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
    
    //Get stats from metadata
    unsigned long long currentTotal = metadata.getU64Value(totalTCCountMetadataKey);
    int crashes = metadata.getUIntValue(totalCrashedCountMetadataKey);
    int hangs = metadata.getUIntValue(totalHungCountMetadataKey);
    int bytesCovered = metadata.getUIntValue(totalBytesCoveredMetadataKey);
    int uniqueTotal = metadata.getUIntValue(uniqueTCCountMetadataKey);
    int uniqueCrashes = metadata.getUIntValue(uniqueCrashedCountMetadataKey);
    int uniqueHangs = metadata.getUIntValue(uniqueHungCountMetadataKey);

    float latestCasePerSec = metadata.getFloatValue(latestExecPerSecMetadataKey);
    float casePerSec  = metadata.getFloatValue(averageExecPerSecMetadataKey);
    float timeSinceLastFound = metadata.getFloatValue(secondsSinceLastUniqueMetadataKey);
    //Output the data
    if(!writeToServer)
    {
        //Statistics are written to the console
        LOG_INFO << "UNIQUE INTERESTING TEST CASES: " << uniqueTotal;
        LOG_INFO << "UNIQUE CRASHES: " << uniqueCrashes << " (" << crashes << " TOTAL)";
        LOG_INFO << "LATEST EXEC/SEC: " << latestCasePerSec << "/s (" << casePerSec << "/s AVERAGE)";
        LOG_INFO << "TIME SINCE LAST FINDING: " << timeSinceLastFound << " seconds";
        LOG_INFO << "TOTAL EXECUTIONS: " << currentTotal;
        LOG_INFO << "UNIQUE HANGS: " << uniqueHangs << " (" << hangs << " TOTAL)";
        LOG_INFO << "COVERED TUPLES: " << bytesCovered;
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
                //TODO(VADER-1443): int is not a large enough data type for many of these values
                Json::object { {"key","uniqueInterestingTestCases"},{"value", (int)uniqueTotal} },
                Json::object { {"key","uniqueCrashes"}, {"value", (int)uniqueCrashes} },
                Json::object { {"key","latestExecPerSec"}, {"value", latestCasePerSec} },
                Json::object { {"key","timeSinceLastFound"}, {"value", timeSinceLastFound} },
                Json::object { {"key","totalExecutions"}, {"value",(int)currentTotal} },
                Json::object { {"key","totalUniqueHangs"}, {"value", (int)uniqueHangs} },
                Json::object { {"key","avgExecPerSec"}, {"value", casePerSec} },
                Json::object { {"key","totalCrashes"}, {"value",(int)crashes} },
                Json::object { {"key","totalHangs"}, {"value", (int)hangs} },
                Json::object { {"key","coveredTuples"}, {"value", (int)bytesCovered} }
                }
            } 
        };

        CDMSClient::getInstance()->sendKPI(jsonObj);
    }
}

