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
#include "CSVMetadataOutput.hpp"
#include "VmfUtil.hpp"
#include <fstream>
#include <iostream>

using namespace vmf;

#include "ModuleFactory.hpp"
REGISTER_MODULE(CSVMetadataOutput);

/**
 * @brief Builder method to support the ModuleFactory
 * Constructs an instance of this class
 * @return Module* 
 */
Module* CSVMetadataOutput::build(std::string name)
{
    return new CSVMetadataOutput(name);
}

void CSVMetadataOutput::init(ConfigInterface& config)
{
    outputRate = config.getIntParam(getModuleName(),"outputRateInSeconds", 5);
    outputFile = config.getOutputDir() + "/" + config.getStringParam(getModuleName(), "outputFileName", "metadata.csv");
}

/**
 * @brief Construct a new Logger Metadata Output object
 * 
 * @param name 
 */
CSVMetadataOutput::CSVMetadataOutput(std::string name) :
    OutputModule(name)
{
    outputRate = 0;
    keysLoaded = false;
}

CSVMetadataOutput::~CSVMetadataOutput()
{

}

void CSVMetadataOutput::registerStorageNeeds(StorageRegistry& registry)
{
    //No non-metadata fields are needed by this module
}

void CSVMetadataOutput::registerMetadataNeeds(StorageRegistry& registry)
{
    //Register to read all the fields from metadata
    registry.registerToReadAllKeys();
}

OutputModule::ScheduleTypeEnum CSVMetadataOutput::getDesiredScheduleType()
{
    return OutputModule::CALL_ON_NUM_SECONDS;
}

int CSVMetadataOutput::getDesiredScheduleRate()
{
    return outputRate;
}

void CSVMetadataOutput::run(StorageModule& storage)
{
    StorageEntry& metadata = storage.getMetadata();

    //One time look-up of the actual keys.  This has to be done in the run method
    //because the full list of keys is not known at registration time
    if(!keysLoaded)
    {
        loadKeyDataAndWriteHeader(storage);
    }

    std::ofstream csvFile;
    csvFile.open(outputFile, std::ios::out | std::ios::app);
    //Always output a timestamp
    csvFile << VmfUtil::getCurTimeSecs() << ",";

    for(int i=0; i<(int)intKeys.size(); i++)
    {
        csvFile << metadata.getIntValue(intKeys[i]) << ",";
    }
    for(int i=0; i<(int)uintKeys.size(); i++)
    {
        csvFile << metadata.getUIntValue(uintKeys[i]) << ",";
    }
    for(int i=0; i<(int)floatKeys.size(); i++)
    {
        csvFile << metadata.getFloatValue(floatKeys[i]) << ",";
    }

    csvFile << "\n";
    csvFile.close();
}

void CSVMetadataOutput::loadKeyDataAndWriteHeader(StorageModule& storage)
{
    std::ofstream csvFile(outputFile);
    csvFile << "Timestamp,";

    intKeys = storage.getListOfMetadataKeyHandles(StorageRegistry::INT);
    uintKeys = storage.getListOfMetadataKeyHandles(StorageRegistry::UINT);
    floatKeys = storage.getListOfMetadataKeyHandles(StorageRegistry::FLOAT);

    intKeyNames.reserve((int)intKeys.size());
    for(int i=0; i<(int)intKeys.size(); i++)
    {
        std::string name = storage.metadataKeyHandleToString(intKeys[i]);
        intKeyNames.push_back(name);
        csvFile << name << ",";
    }
    uintKeyNames.reserve((int)uintKeys.size());
    for(int i=0; i<(int)uintKeys.size(); i++)
    {
        std::string name = storage.metadataKeyHandleToString(uintKeys[i]);
        uintKeyNames.push_back(name);
        csvFile << name << ",";
    }
    floatKeyNames.reserve((int)floatKeys.size());
    for(int i=0; i<(int)floatKeys.size(); i++)
    {
        std::string name = storage.metadataKeyHandleToString(floatKeys[i]);
        floatKeyNames.push_back(name);
        csvFile << name << ",";
    }

    keysLoaded = true;
    csvFile << "\n";
    csvFile.close();

}
