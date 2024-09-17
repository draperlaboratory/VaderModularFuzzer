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
#include "LoggerMetadataOutput.hpp"
#include "Logging.hpp"

using namespace vmf;

#include "ModuleFactory.hpp"
REGISTER_MODULE(LoggerMetadataOutput);

/**
 * @brief Builder method to support the ModuleFactory
 * Constructs an instance of this class
 * @return Module* 
 */
Module* LoggerMetadataOutput::build(std::string name)
{
    return new LoggerMetadataOutput(name);
}

void LoggerMetadataOutput::init(ConfigInterface& config)
{
    outputRate = config.getIntParam(getModuleName(),"outputRateInSeconds", 5);
}

/**
 * @brief Construct a new Logger Metadata Output object
 * 
 * @param name 
 */
LoggerMetadataOutput::LoggerMetadataOutput(std::string name) :
    OutputModule(name)
{
    outputRate = 0;
    keysLoaded = false;
}

LoggerMetadataOutput::~LoggerMetadataOutput()
{

}

void LoggerMetadataOutput::registerStorageNeeds(StorageRegistry& registry)
{
    //No non-metadata fields are needed by this module
}

void LoggerMetadataOutput::registerMetadataNeeds(StorageRegistry& registry)
{
    //Register to read all the fields from metadata
    registry.registerToReadAllKeys();
}

OutputModule::ScheduleTypeEnum LoggerMetadataOutput::getDesiredScheduleType()
{
    return OutputModule::CALL_ON_NUM_SECONDS;
}

int LoggerMetadataOutput::getDesiredScheduleRate()
{
    return outputRate;
}

void LoggerMetadataOutput::run(StorageModule& storage)
{
    StorageEntry& metadata = storage.getMetadata();

    //One time look-up of the actual keys.  This has to be done in the run method
    //because the full list of keys is not known at registration time
    if(!keysLoaded)
    {
        loadKeyData(storage);
    }

    for(int i=0; i<(int)intKeys.size(); i++)
    {
        LOG_INFO << intKeyNames[i] << ": " << metadata.getIntValue(intKeys[i]);
    }
    for(int i=0; i<(int)uintKeys.size(); i++)
    {
        LOG_INFO << uintKeyNames[i] << ": " << metadata.getUIntValue(uintKeys[i]);
    }
    for(int i=0; i<(int)floatKeys.size(); i++)
    {
        LOG_INFO << floatKeyNames[i] << ": " << metadata.getFloatValue(floatKeys[i]);
    }
   
    LOG_INFO << "------------------------------------";
}

void LoggerMetadataOutput::loadKeyData(StorageModule& storage)
{
    intKeys = storage.getListOfMetadataKeyHandles(StorageRegistry::INT);
    uintKeys = storage.getListOfMetadataKeyHandles(StorageRegistry::UINT);
    floatKeys = storage.getListOfMetadataKeyHandles(StorageRegistry::FLOAT);

    intKeyNames.reserve((int)intKeys.size());
    for(int i=0; i<(int)intKeys.size(); i++)
    {
        intKeyNames.push_back(storage.metadataKeyHandleToString(intKeys[i]));
    }
    uintKeyNames.reserve((int)uintKeys.size());
    for(int i=0; i<(int)uintKeys.size(); i++)
    {
        uintKeyNames.push_back(storage.metadataKeyHandleToString(uintKeys[i]));
    }
    floatKeyNames.reserve((int)floatKeys.size());
    for(int i=0; i<(int)floatKeys.size(); i++)
    {
        floatKeyNames.push_back(storage.metadataKeyHandleToString(floatKeys[i]));
    }

    keysLoaded = true;
}
