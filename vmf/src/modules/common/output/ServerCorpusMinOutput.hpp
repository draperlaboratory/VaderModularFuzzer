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
#include "RuntimeException.hpp"
//#include "AFLExecutor.hpp"
#include <string>

namespace vmf
{
  
/**
 * @brief Output module that transmits a minimized corpus to the server
 * 
 * This module only makes sense in the context of a controller that is being
 * used just to perform corpus minimization on the common corpus (e.g. AnalysisController).
 * 
 * This module relies on a submodule that perform the actual corpus minimization.
 * In the run method, this module will call upon the submodule's run method with the
 * expectation that the submodule will minimize the corpus.  At shutdown, this module
 * sends the list of URLs associated with the current (just minimized) corpus to the server.
 * This module requires the FILE_URL field to be provided for each test case in storage.
 * @image html CoreModuleDataModel_9.png width=800px
 * @image latex CoreModuleDataModel_9.png width=6in
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
    bool minimizationRan;

};
}
