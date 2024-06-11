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
#include "ControllerModule.hpp"
#include "CDMSClient.hpp"
#include "Logging.hpp"
#include "VmfUtil.hpp"
#include <ctime>
#include <ratio>
#include <chrono>

using namespace vmf;

ControllerModule::ControllerModule(std::string name) : 
    StorageUserModule(name, ModuleTypeEnum::CONTROLLER) 
{

};

void ControllerModule::init(ConfigInterface& config)
{
    //Note: These parameters are really only needed for distributed fuzzing mode
    lastCorpusUpdate = std::chrono::system_clock::now();
    initialCorpusSyncComplete = false;
    corpusUpdateRateMins = config.getIntParam(getModuleName(),"corpusUpdateRateMins", 5);
    corpusInitialUpdateMins = config.getIntParam(getModuleName(), "corpusInitialUpdateMins", 5);
    if(corpusUpdateRateMins<1)
    {
        LOG_WARNING << "Distributed Fuzzing -- Minimum corpus update increased to 1 minute";
        corpusUpdateRateMins = 1;
    }
    LOG_INFO << "Distributed Fuzzing -- Minimum corpus update rate is " << corpusUpdateRateMins;

    if(corpusInitialUpdateMins<1)
    {
        LOG_WARNING << "Distributed Fuzzing -- Initial corpus update time increased to 1 minute";
        corpusInitialUpdateMins = 1;
    }
    LOG_INFO << "Distributed Fuzzing -- Initial corpus update time is " << corpusInitialUpdateMins;

    std::vector<std::string> defaultTags = {"RAN_SUCCESSFULLY"};
    std::vector<std::string> updateTags = config.getStringVectorParam(getModuleName(),"corpusUpdateTags", defaultTags);
    tags = CDMSClient::getInstance()->formatTagList(updateTags);
    LOG_INFO << "Distributed Fuzzing -- Corpus update will retrieve tags=" << tags;

};

void ControllerModule::registerStorageNeeds(StorageRegistry& registry)
{
   serverTestCaseTag = registry.registerTag("SERVER_TC", StorageRegistry::WRITE_ONLY);
   testCaseKey = registry.registerKey("TEST_CASE", StorageRegistry::BUFFER, StorageRegistry::READ_WRITE);
    //Technically the testCaseKey is only written, but subclasses of this class will also READ it
    //(such as the IterativeController)
};


void ControllerModule::handleCommand(StorageModule& storage, bool isDistributed, ControllerCmdType cmd)
{
    if(isDistributed)
    {
        if(ControllerCmdType::NEW_CORPUS == cmd)
        {
            //Determine how long it has been since the last corpus update
            std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
            std::chrono::duration<double> elapsed = now - lastCorpusUpdate;
            int elapsedMin = (int)elapsed.count()/60;

            //See if enough time has passed that we should perform a corpus update
            int threshold = corpusUpdateRateMins;
            if(!initialCorpusSyncComplete){
                //Use a different time threshold for the first corpus update
                threshold = corpusInitialUpdateMins;
            }
            if(elapsedMin >= threshold)
            {
                LOG_DEBUG << "Performing corpus update.";
                CDMSClient* client = CDMSClient::getInstance();
                initialCorpusSyncComplete = true;
                lastCorpusUpdate = now;
                json11::Json json = client->getCorpusUpdates(tags);
                //A new test case is created for each test case on the file list, with the
                //"SERVER_TC" tag set so it is flagged as coming from the server
                CDMSClient::getInstance()->createNewTestCasesFromJson(storage, json, testCaseKey, serverTestCaseTag);
            }
        }
        else
        {
            LOG_ERROR << "Unknown command type: " << cmd;
        }
    }
}

//------ Standard Static Module Convenience Methods ------//

ControllerModule* ControllerModule::getControllerSubmodule(ConfigInterface& config, std::string parentName)
{
    ControllerModule* theModule = nullptr;
    std::vector<Module*> modules = config.getSubModules(parentName);
    for(Module* m: modules)
    {
        if(isAnInstance(m))
        {
            if(nullptr == theModule)
            {
                theModule = castTo(m);
            }
            else
            {
                throw RuntimeException(
                    "Configuration file contained more than one Controller module, but only one is supported",
                    RuntimeException::CONFIGURATION_ERROR);
            }
            
        }
    }
    return theModule;
}

ControllerModule* ControllerModule::getControllerSubmoduleByName(ConfigInterface& config, std::string parentName, std::string childName)
{
    ControllerModule* theModule = nullptr;
    std::vector<Module*> modules = config.getSubModules(parentName);
    for(Module* m: modules)
    {
        if(childName == m->getModuleName())
        {
            if(isAnInstance(m))
            {
                theModule = castTo(m);
                break;
            }
            else
            {
                LOG_ERROR << parentName << " requested an Controller submodule named " << childName 
                            << ", but that submodules is not of type Controller.";
                throw RuntimeException(
                    "Configuration file contained a module with this name, but it was not an executor module",
                    RuntimeException::CONFIGURATION_ERROR);
            }
        }
    }
    
    return theModule;
}

std::vector<ControllerModule*> ControllerModule::getControllerSubmodules(ConfigInterface& config, std::string parentName)
{
    std::vector<ControllerModule*> list;
    std::vector<Module*> modules = config.getSubModules(parentName);
    for(Module* m: modules)
    {
        if(isAnInstance(m))
        {
            list.push_back(castTo(m));
        }
    }
    return list;
}

bool ControllerModule::isAnInstance(Module* module)
{
    ModuleTypeEnum type = module->getModuleType();
    return (ModuleTypeEnum::CONTROLLER == type);
}

ControllerModule* ControllerModule::castTo(Module* module)
{
    ControllerModule* c;
    if(nullptr != module)
    {
        c = dynamic_cast<ControllerModule*>(module);
    
        if(nullptr == c)
        {
            throw RuntimeException("Failed attempt to cast module to Controller",
                                RuntimeException::USAGE_ERROR);
        }
    }
    else
    {
        throw RuntimeException("Attempt to cast nullptr to Controller",
                                RuntimeException::UNEXPECTED_ERROR);
    }
    
    return c;
}
