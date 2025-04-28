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
#include "ServerCorpusInitialization.hpp"
#include "Logging.hpp"
#include "CDMSClient.hpp"
#include "CDMSCommandAndCorpusHandler.hpp"


using namespace vmf;

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
    CDMSCommandAndCorpusHandler::getInstance().registerStorageNeeds(registry);

    if(writeServerURL)
    {
        fileURLKey = registry.registerKey("FILE_URL", StorageRegistry::BUFFER, StorageRegistry::WRITE_ONLY);
    } else {
        fileURLKey = -1; //This is not to be used
    }
}


void ServerCorpusInitialization::run(StorageModule& storage)
{

   
    LOG_INFO << "About to request whole corpus from CDMS";
    bool done = CDMSCommandAndCorpusHandler::getInstance().loadWholeCorpus(storage, tags, fileURLKey);
    if(!done)
    {
        throw RuntimeException("Unable to load whole corpus due to error in CDMSCommandAndCorpusHandler", RuntimeException::UNEXPECTED_ERROR);
    }
}

