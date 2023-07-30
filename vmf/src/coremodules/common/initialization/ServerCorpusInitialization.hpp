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
#pragma once

#include "InitializationModule.hpp"
#include "VaderUtil.hpp"

namespace vader
{

/**
 * @brief Initialization using the whole corpus, as retrieved from the server
 * This is distinct from ServerSeedInitialization in that the whole corpus is
 * always retrieved from the server (though it may be filtered by tag).  This is useful
 * primarily for VMF configurations that minimize the corpus.
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
        int    testCaseKey;
        int    mutatorIdKey;
        int    fileURLKey;

        std::string tags;
};
}