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
#include "ServerSeedInitialization.hpp"
#include "Logging.hpp"
#include "CDMSClient.hpp"
#include "CDMSCommandAndCorpusHandler.hpp"


using namespace vmf;

#include "ModuleFactory.hpp"
REGISTER_MODULE(ServerSeedInitialization);

/**
 * @brief Constructor
 * initialize the set of strings in the SUT
 * 
 * @param name the name of the module.
 */
ServerSeedInitialization::ServerSeedInitialization(std::string name) :
    InitializationModule(name)
{}


ServerSeedInitialization::~ServerSeedInitialization()
{}

/**
 * @brief builder method to support the `ModuleFactory`
 * Constructs an instance of the class, and returns a pointer to the caller.
 * 
 * @param name the name of the module.
 */
Module* ServerSeedInitialization::build(std::string name)
{
    return new ServerSeedInitialization(name);
}


void ServerSeedInitialization::init(ConfigInterface& config)
{
    std::vector<std::string> defaultTags = {"RAN_SUCCESSFULLY"};
    std::vector<std::string> updateTags = config.getStringVectorParam(getModuleName(),"corpusTags", defaultTags);
    tags = CDMSClient::getInstance()->formatTagList(updateTags);
    getMinCorpus = config.getBoolParam(getModuleName(), "getMinCorpus", true);

}


void ServerSeedInitialization::registerStorageNeeds(StorageRegistry& registry)
{
    CDMSCommandAndCorpusHandler::getInstance().registerStorageNeeds(registry);
}


void ServerSeedInitialization::run(StorageModule& storage)
{
    LOG_INFO << "About to request initial seeds from CDMS";
    CDMSCommandAndCorpusHandler::getInstance().loadCorpusInitialSeeds(storage,tags,getMinCorpus);
}

