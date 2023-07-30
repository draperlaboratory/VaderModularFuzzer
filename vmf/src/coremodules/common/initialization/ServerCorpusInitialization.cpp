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
#include "ServerCorpusInitialization.hpp"
#include "Logging.hpp"
#include "CDMSClient.hpp"
#include "json11.hpp"


using namespace vader;

#include "ModuleFactory.hpp"
REGISTER_MODULE(ServerCorpusInitialization);

/**
 * @brief Constructor
 * initialize the set of strings in the SUT
 * 
 * @param name the name of the module.
 */
ServerCorpusInitialization::ServerCorpusInitialization(std::string name) :
    InitializationModule(name)
{}


ServerCorpusInitialization::~ServerCorpusInitialization()
{}

/**
 * @brief builder method to support the `ModuleFactory`
 * Constructs an instance of the class, and returns a pointer to the caller.
 * 
 * @param name the name of the module.
 */
Module* ServerCorpusInitialization::build(std::string name)
{
    return new ServerCorpusInitialization(name);
}


void ServerCorpusInitialization::init(ConfigInterface& config)
{
    //When true, stores a copy of the URL associated with the file in storage
    writeServerURL = config.getBoolParam(getModuleName(), "writeServerURL", true);

    std::vector<std::string> defaultTags = {""}; //default to retrieving all tags
    std::vector<std::string> updateTags = config.getStringVectorParam(getModuleName(),"corpusTags", defaultTags);
    tags = CDMSClient::getInstance()->formatTagList(updateTags);

}


void ServerCorpusInitialization::registerStorageNeeds(StorageRegistry& registry)
{
    testCaseKey = registry.registerKey("TEST_CASE",StorageRegistry::BUFFER,StorageRegistry::WRITE_ONLY);
    mutatorIdKey = registry.registerKey("MUTATOR_ID", StorageRegistry::INT, StorageRegistry::WRITE_ONLY);
       
    if(writeServerURL)
    {
        fileURLKey = registry.registerKey("FILE_URL", StorageRegistry::BUFFER, StorageRegistry::WRITE_ONLY);
    } else {
        fileURLKey = -1; //This is not to be used
    }
}


void ServerCorpusInitialization::run(StorageModule& storage)
{

    CDMSClient* client = CDMSClient::getInstance();
   
    LOG_INFO << "About to request whole corpus from CDMS";
    json11::Json json = client->getCorpus(tags);

    auto fileList    = json["files"].array_items();
    int  size        = fileList.size();

    LOG_INFO << "Received a corpus of size " << size;

    for(int i=0; i<size; i++)
    {
        auto fileJson = fileList[i];

        std::string     contents    = client->getCorpusFile(fileJson.string_value());   
        StorageEntry*   entry       = storage.createNewEntry();
        char*           buff        = entry->allocateBuffer(testCaseKey, contents.length());

        contents.copy(buff, contents.length());

        //A mutator id of SERVER_MUTATOR_ID will indicate that this is a server provided test case,
        //as opposed to one that is generated internally within this VMF instance
        entry->setValue(mutatorIdKey, CDMSClient::SERVER_MUTATOR_ID);

        //The server URL is written to storage
        if(writeServerURL)
        {
            std::string fileURL = fileJson.string_value();
            char* urlBuff = entry->allocateBuffer(fileURLKey, fileURL.length());
            fileURL.copy(urlBuff,fileURL.length());
        }
    }
}

