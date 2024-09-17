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
#include "VmfRand.hpp"

namespace vmf
{
/**
 * @brief Generates new test case by picking a recursive feature and expanding it up to RECUR_THRESHOLD times
 * 
 * This mutator picks a random test case and attempts to find recursive features of the test case 
 * to expand out. If no recursive features are found, it will do a random walk mutation instead.
 * 
 */
class GramatronRecursiveMutator: public MutatorModule
{
public:

    static Module* build(std::string name);
    virtual void init(ConfigInterface& config);

    GramatronRecursiveMutator(std::string name);
    virtual ~GramatronRecursiveMutator();
    virtual void registerStorageNeeds(StorageRegistry& registry);
    virtual void mutateTestCase(StorageModule& storage, StorageEntry* baseEntry, StorageEntry* newEntry, int testCaseKey);

private:
    int autRepKey;
    PDA* pda;
    VmfRand* rand;
    void recursive(StorageEntry* newEntry, char* buffer, int testCaseKey);

    void random(StorageEntry* newEntry, char* buffer, int testCaseKey);

    Array* doMult(Array* input, UT_array** recur, int recurlen);

    void getTwoIndices(UT_array* recur, int recurlen, int* firstIdx, int* secondIdx);
    void swap(int *a, int *b);
};
}
