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
#include "ServerCorpusMinOutput.hpp"
#include "VmfUtil.hpp"
#include "Logging.hpp"
#include "CDMSClient.hpp"


using namespace vmf;

#include "ModuleFactory.hpp"
REGISTER_MODULE(ServerCorpusMinOutput);

/**
 * @brief Builder method to support the ModuleFactory
 * Constructs an instance of this class
 * @return Module* 
 */
Module* ServerCorpusMinOutput::build(std::string name)
{
    return new ServerCorpusMinOutput(name);
}

/**
 * @brief Initialization method
 * Finds an executor instance to run testcases with and resets state.
 * 
 * @param config 
 */
void ServerCorpusMinOutput::init(ConfigInterface& config)
{
    corpusMinModule = OutputModule::getOutputSubmodule(config,getModuleName());

    //This requests that the other fuzzers in this cluster should pause
    //(so that minimization can be performed)
    CDMSClient::getInstance()->requestPauseFuzzers();
}

/**
 * @brief Construct a new ServerCorpusMinOutput module
 * 
 * @param name 
 */
ServerCorpusMinOutput::ServerCorpusMinOutput(std::string name):
    OutputModule(name)
{
    minimizationRan = false;
}

/**
 * @brief Destructor
 * 
 */
ServerCorpusMinOutput::~ServerCorpusMinOutput()
{

}

void ServerCorpusMinOutput::registerStorageNeeds(StorageRegistry& registry)
{
    fileURLKey = registry.registerKey("FILE_URL", StorageRegistry::BUFFER, StorageRegistry::READ_ONLY);
}

void ServerCorpusMinOutput::run(StorageModule& storage)
{
    //Call on the corpus min submodule to minimize the corpus
    minimizationRan = false;
    corpusMinModule->run(storage);
    minimizationRan = true; 
    //The minimizationRan variable is needed in case corpus minimization throws an exception
    //because in distributed mode, we will start to shutdown when there is an exception
    //and then immediately receive a stop command from the server.  This was leading to a double
    //free on the modules, because the shutdown method in this module was slow running.

    //Note: If we ever want to be able to minimize the common corpus periodically,
    //such that this module could be included in something other than a controller that only runs once,
    //it should be possible to refactor this module to perform that behavior instead.
    //
    //However, if doing this, it is important to note that items are not deleted from
    //storage until storage.clearNewAndLocalEntries is called.  So you cannot call on the submodule
    //to minimize and then immediate push to the server.  Instead, you would need to do something
    //like minimize on one pass of the output module and push to storage on the next.
}

void ServerCorpusMinOutput::shutdown(StorageModule& storage)
{
    if(minimizationRan)
    {
        //Publish the current corpus (which should have been just minimized) to the server
        std::vector<std::string> files;

        std::unique_ptr<Iterator> allEntries = storage.getSavedEntries();
        while(allEntries->hasNext())
        {
            StorageEntry* theEntry = allEntries->getNext();
            char* buff = theEntry->getBufferPointer(fileURLKey);
            int size = theEntry->getBufferSize(fileURLKey);
            std::string url;
            url.assign(buff,buff+size);
            files.push_back(url);
        }
        
        CDMSClient::getInstance()->requestCorpusSync(files, true); //sync at the cluster level
    }
    else
    {
        LOG_ERROR << "Corpus Minimization did not run properly, so no updated corpus will be sent to the server.";
    }
}
