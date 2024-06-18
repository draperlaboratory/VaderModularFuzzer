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
#include "RuntimeException.hpp"
//#include "AFLExecutor.hpp"
#include <string>

namespace vmf
{
  
/**
 * @brief Output module that transmits a minimized corpus to the server
 * 
 * This module only makes sense in the context of a RunOnceController that is being
 * used just to perform corpus minimization on the common corpus.
 * 
 * This module relies on a submodule that perform the actual corpus minimization.
 * In the run method, this module will call upon the submodule's run method with the
 * expectation that the submodule will minimize the corpus.  At shutdown, this module
 * sends the list of URLs associated with the current (just minimized) corpus to the server.
 * This module requires the FILE_URL field to be provided for each test case in storage.
 */
class ServerCorpusMinOutput : public OutputModule {
public:
    static Module* build(std::string name);
    virtual void init(ConfigInterface& config);

    ServerCorpusMinOutput(std::string name);
    virtual ~ServerCorpusMinOutput();

    virtual void registerStorageNeeds(StorageRegistry& registry);

    virtual void run(StorageModule& storage);
    virtual void shutdown(StorageModule& storage);
private:
    int fileURLKey;
    OutputModule* corpusMinModule;

};
}
