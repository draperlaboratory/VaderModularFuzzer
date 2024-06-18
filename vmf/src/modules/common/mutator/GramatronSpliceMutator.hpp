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
 * @brief Pick two test cases and attempt to splice them together at an appropriate yet randomly chosen point.
 * 
 * This mutator picks two random interesting test cases and attempts to find appropriate splice points 
 * in each test case to append the front of one test case to the tail of the other to make a new 
 * interesting test case to put into mutateTestCase.
 * 
 */
class GramatronSpliceMutator: public MutatorModule
{
public:

    static Module* build(std::string name);
    virtual void init(ConfigInterface& config);

    GramatronSpliceMutator(std::string name);
    virtual ~GramatronSpliceMutator();
    virtual void registerStorageNeeds(StorageRegistry& registry);
    virtual void mutateTestCase(StorageModule& storage, StorageEntry* baseEntry, StorageEntry* newEntry, int testCaseKey);

private:
    int autRepKey;
    int normalTag;
    PDA* pda;

    void splice(StorageEntry* newEntry, StorageEntry* baseEntry, StorageModule& storage, int testCaseKey);

    Array* performSpliceOne(Array* originput, IdxMap_new* statemap_orig, Array* splicecand);
};
}