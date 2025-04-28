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
 * @brief Initialization using `strings` utility to create fuzzer dictionary to
 *        mutate test cases with
 */
class DictionaryInitialization: public InitializationModule {
public: 
    static Module* build(std::string name);
    virtual void init(ConfigInterface& config);
    virtual void registerStorageNeeds(StorageRegistry& registry);
    virtual void run(StorageModule& storage);

    DictionaryInitialization(std::string name);
    virtual ~DictionaryInitialization();
private:
    std::string sut_path;
    std::string output_base;
    
    // TODO: the hard-coded dictionary path shared with the DictionaryInitialization
    // TODO: module.  Hard-coded to synthesize updates to storage module while 
    // TODO: refactor to support other datatypes pends (VADER-1420)
    std::string dictionary_path_hardcode;
};
}