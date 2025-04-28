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
#pragma once


#include "OutputModule.hpp"
#include <map>

namespace vmf
{
/**
 * @brief OutputModule that publishes corpus data to the Campaign Data Management Server.
 * All interesting test cases are published, including any tags.  Test cases with the
 * SERVER_TC tag are excluded, as these were test cases that came from the server originally.
 * The SEND_TO_SERVER tag is used by this module to manage the set of test cases that should
 * be sent to the server at any given point in time.
 * @image html CoreModuleDataModel_9.png width=800px
 * @image latex CoreModuleDataModel_9.png width=6in
 */
class ServerCorpusOutput : public OutputModule{
public:
    static Module* build(std::string name);
    virtual void init(ConfigInterface& config);
    virtual void registerStorageNeeds(StorageRegistry& registry);
    virtual void run(StorageModule& storage);

    ServerCorpusOutput(std::string name);
    virtual ~ServerCorpusOutput();

private:

    std::string generateTagList(StorageModule& storage, StorageEntry* entry);
    void sendEntries(StorageModule& storage);

    /// Counts the storage entries that should be sent to the server
    int numEntriesToSend;

    /// How long to wait between test cases send to the server
    int serverDelayTimeInSecs;

    /// Override the time to wait if there are a lot of test cases (this limits the number sent at once), set to -1 to not use this override
    int serverDelayOverrideCount;

    /// How long it's been since the last send
    time_t lastTimeSent;
    
    /// The tag for test cases that came from the CDMS server
    int serverTestCaseTag;

    /// The handle for the test case buffer
    int testCaseKey;

    /// The handle for test cases that should be sent to the server
    int sendToServerTag;

    std::map<int,std::string> tagNameMap;
};
}