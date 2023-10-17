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

/**
 * @brief Pick a random symbol in the test case to do a new random walk from in the PDA.
 * 
 * This mutator pulls interesting test cases from storage and picks a random place in the 
 * automata walk representation of the test case to regenerate the end of the walk from.
 */
class GramatronRandomMutator: public MutatorModule
{
public:

    static Module* build(std::string name);
    virtual void init(ConfigInterface& config);

    GramatronRandomMutator(std::string name);
    virtual ~GramatronRandomMutator();
    virtual void registerStorageNeeds(StorageRegistry& registry);
    virtual StorageEntry* createTestCase(StorageModule& storage, StorageEntry* baseEntry);

private:
    int testCaseKey;
    int autRepKey;
    PDA* pda;

    void random(StorageEntry* newEntry, char* buffer);
};