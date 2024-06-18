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
#pragma once


#include "OutputModule.hpp"
#include <map>

namespace vmf
{
/**
 * @brief Output module that publishes corpus data to the Campaign Data Management Server
 * All interesting test cases are published, including any tags.
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