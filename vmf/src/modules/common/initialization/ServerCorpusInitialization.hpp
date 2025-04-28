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

#include "InitializationModule.hpp"
#include "VmfUtil.hpp"

namespace vmf
{

/**
 * @brief InitializationModule using the whole corpus, as retrieved from the server.
 * This is distinct from ServerSeedInitialization in that the whole corpus is
 * always retrieved from the server (though it may be filtered by tag).  This is useful
 * primarily for VMF configurations that minimize the corpus.  The FILE_URL will be
 * optionally written, if specified in the config file (this is the URL of the file as
 * provided by the server).
 * 
 * This module uses CDMSCommandAndCorpusHandler to facilitate its corpus loading and management.
 * @image html CoreModuleDataModel_9.png width=800px
 * @image latex CoreModuleDataModel_9.png width=6in
 */
class ServerCorpusInitialization: public InitializationModule 
{
    public: 
        static Module*  build(std::string name);
        virtual void    init(ConfigInterface& config);
        virtual void    registerStorageNeeds(StorageRegistry& registry);
        virtual void    run(StorageModule& storage);

        ServerCorpusInitialization(std::string name);
        virtual ~ServerCorpusInitialization();

    private:
        bool   writeServerURL;
        int    fileURLKey;

        std::string tags;
};
}