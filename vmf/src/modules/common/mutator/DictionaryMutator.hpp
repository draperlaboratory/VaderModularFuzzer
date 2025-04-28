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

#include <fstream>

#include "MutatorModule.hpp"
#include "StorageEntry.hpp"
#include "VmfRand.hpp"

namespace vmf{

/**
 * @brief Generates test cases by randomly inserting user defined strings
 * The user defined strings can be specified in an input file, or this module
 * can be paired with DictionaryInitialization to automatically generate
 * strings of interest.
 */
class DictionaryMutator : public MutatorModule
{
public:
    static Module* build(std::string name);
    virtual void init(ConfigInterface& config);
    
    DictionaryMutator(std::string name);
    virtual ~DictionaryMutator();
    virtual void registerStorageNeeds(StorageRegistry& registry);

    virtual void mutateTestCase(StorageModule& storage, StorageEntry* baseEntry, StorageEntry* newEntry, int testCaseKey);
    
    // Function to parse in the strings list.  Made public to serve as test of
    // formatting of tokens list.
    static void get_tokens(std::string dictionary_path, std::vector<char*>& lines);
private:
    void initialize_lines();

    std::vector<std::string> dictionary_paths;
    std::vector<char*> lines;
    // TODO: the hard-coded dictionary path shared with the DictionaryInitialization
    // TODO: module.  Hard-coded to synthesize updates to storage module while 
    // TODO: refactor to support other datatypes pends (VADER-1420)
    std::string dictionary_path_hardcode;
    VmfRand* rand;
};
}


