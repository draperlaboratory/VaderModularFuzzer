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
#include "ServerCorpusOutput.hpp"
#include "CDMSClient.hpp"

using namespace vader;

#include "ModuleFactory.hpp"
REGISTER_MODULE(ServerCorpusOutput);

/**
 * @brief Builder method to support the ModuleFactory
 * Constructs an instance of this class
 * @return Module* 
 */
Module* ServerCorpusOutput::build(std::string name)
{
    return new ServerCorpusOutput(name);
}

/**
 * @brief Initialization method
 * Reads in all configuration options for this class
 * 
 * @param config 
 */
void ServerCorpusOutput::init(ConfigInterface& config)
{
   serverDelayTimeInSecs = config.getIntParam(getModuleName(), "serverDelayTimeinSecs", 30);
   //A value of -1 indicates that this override should not be used
   serverDelayOverrideCount = config.getIntParam(getModuleName(), "serverDelayOverrideCount", -1);
   lastTimeSent = time(0);
   numEntriesToSend = 0;
}

/**
 * @brief Construct a new ServerCorpusOutput module
 * 
 * @param name 
 */
ServerCorpusOutput::ServerCorpusOutput(std::string name):
    OutputModule(name)
{

}

/**
 * @brief Destructor
 * 
 */
ServerCorpusOutput::~ServerCorpusOutput()
{

}

void ServerCorpusOutput::registerStorageNeeds(StorageRegistry& registry)
{
    registry.registerForAllTags(StorageRegistry::READ_ONLY);
    sendToServerTag = registry.registerTag("SEND_TO_SERVER", StorageRegistry::READ_WRITE);
    testCaseKey = registry.registerKey("TEST_CASE", StorageRegistry::BUFFER, StorageRegistry::READ_ONLY);
    mutatorIdKey = registry.registerKey("MUTATOR_ID", StorageRegistry::INT, StorageRegistry::WRITE_ONLY);
}

void ServerCorpusOutput::run(StorageModule& storage)
{

    //Check to see if the tagNameMap has been initialized
    //This occurs on the first run, because we need to know the full list of tag names that have
    //been registered with storage
    if(0 == tagNameMap.size())
    {
        std::vector<int> handles = storage.getListOfTagHandles();
        for(int handle: handles)
        {
            if(sendToServerTag != handle) //don't send the server the send to server tag
            {
                tagNameMap[handle] = storage.tagHandleToString(handle);
            }
        }
    }

    //Retrieve any new interesting entries and send them to the server, along with their tags
    std::unique_ptr<Iterator> interestingEntries = storage.getNewEntriesThatWillBeSaved();
    while(interestingEntries->hasNext())
    {
        StorageEntry* entry = interestingEntries->getNext();

        //First check that this is an internally generated test case.  If
        //the mutator ID is -1, then we know that the test case was generated outside
        //of this VMF instance, and there is no point in sending it to the server
        //(since that's where it came from in the first place)
        if(-1 == entry->getIntValue(mutatorIdKey))
        {
            //Do not send this test case to the server
            continue;
        }

        //Tag the entry as something we should send
        numEntriesToSend++;
        storage.tagEntry(entry, sendToServerTag);

    }

    //If we have anything to send, and it has been serverDelayTimeInSecs since we last found something,
    //then we can go ahead and send the test cases that were found.  We will also go ahead and send the
    //test cases if we have found serverDelayOverrideCount number of interesting test cases (even if
    //we haven't hit the delay time) -- this is used to prevent a really large zip file from being sent to
    //the server
    if(numEntriesToSend>0)
    {
        time_t now = time(0);
        double elapsed = difftime(now, lastTimeSent);
        if((elapsed >= serverDelayTimeInSecs)||
           ((serverDelayOverrideCount > 0) & (numEntriesToSend >= serverDelayOverrideCount)))
        {
           sendEntries(storage);
           numEntriesToSend = 0;
           lastTimeSent = now;
        }
    }

}

/**
 * @brief Helper method to send the previously tagged entries to storage
 * 
 * The sendToServerTag is cleared on these entries immediately after sending them
 * 
 * @param storage 
 */
void ServerCorpusOutput::sendEntries(StorageModule& storage)
{
    CDMSClient* client = CDMSClient::getInstance();

    std::unique_ptr<Iterator> entriesToSend = storage.getEntriesByTag(sendToServerTag);
    if(entriesToSend->getSize() == 1)
    {
        //Just send the one entry by itself
        StorageEntry* entry = entriesToSend->getNext();
        int size = entry->getBufferSize(testCaseKey);
        char* buffer = entry->getBufferPointer(testCaseKey);

        std::string tagList = generateTagList(storage,entry);

        //Note: Formatted version of the test cases are not provided to the server
        client->sendTestCase(buffer,size,tagList);
    }
    else
    {
        //Package it up as a zip file instead
        //First create the tag name strings
        std::vector<std::string> tagNames;
        while(entriesToSend->hasNext())
        {  
            StorageEntry* entry = entriesToSend->getNext();
            tagNames.push_back(generateTagList(storage,entry));
        }
        entriesToSend->reset();

        //Now pass it all to cdms client to send
        client->sendTestCases(entriesToSend, tagNames, testCaseKey);
    }

    //Clear all the tags on the just sent entries
    entriesToSend->reset();
    while(entriesToSend->hasNext())
    {
        storage.unTagEntry(entriesToSend->getNext(), sendToServerTag);
    }
}

/**
 * @brief Helper method to generate the list of tags for the provided entry
 * These will be formatted as a list of strings for use in communicating
 * the tags to the server
 * 
 * @param storage a reference to the storage module
 * @param entry the entry of interest
 * @return std::string that is the formatted tag list, or the empty string if there are no tags
 */
std::string ServerCorpusOutput::generateTagList(StorageModule& storage, StorageEntry* entry)
{
    std::string tagList = "";
    std::vector<int> tags = storage.getEntryTagList(entry);
    std::vector<std::string> tagNames;
    int numTags = tags.size();
    for(int i=0; i<numTags; i++)
    {
        int tagId = tags[i];
        tagNames.push_back(tagNameMap[tagId]);
    }

    return CDMSClient::getInstance()->formatTagList(tagNames);
}






