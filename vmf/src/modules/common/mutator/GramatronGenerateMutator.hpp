/* =============================================================================
 * Copyright (c) 2023 Vigilant Cyber Systems
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

// main includes
#include "GramatronHelpers.hpp"
#include "MutatorModule.hpp"
#include "StorageEntry.hpp"
#include "RuntimeException.hpp"

namespace vmf
{

/**
 * @brief Generates new test cases from the configured PDA grammar
 * 
 * This mutator uses the pushdown automata singleton class which is instatiated from the 
 * grammar defined in the config file to generate new test cases and add them into storage. 
 * This mutator should always be enabled to keep the fuzzer from getting stuck by not exploring 
 * some parts of the grammar.
 * 
 */
class GramatronGenerateMutator: public MutatorModule
{
public:

    static Module* build(std::string name);
    virtual void init(ConfigInterface& config);

    GramatronGenerateMutator(std::string name);
    virtual ~GramatronGenerateMutator();
    virtual void registerStorageNeeds(StorageRegistry& registry);
    virtual void mutateTestCase(StorageModule& storage, StorageEntry* baseEntry, StorageEntry* newEntry, int testCaseKey);

private:
    int autRepKey;
    PDA* pda;

    void generate(StorageEntry* newEntry, int testCaseKey);
};
}