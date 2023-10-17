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
#include "GramatronGenerateMutator.hpp"
#include <random>
#include <algorithm>
#include <unistd.h>

using namespace vader;

#include "ModuleFactory.hpp"
REGISTER_MODULE(GramatronGenerateMutator);

/**
 * @brief Builder method to support the ModuleFactory
 * Constructs an instance of this class
 * @return Module* 
 */
Module* GramatronGenerateMutator::build(std::string name)
{
    return new GramatronGenerateMutator(name);
}

/**
 * @brief Initialization method
 * 
 * @param config 
 */
void GramatronGenerateMutator::init(ConfigInterface& config)
{
    pda = PDA::GetInstance();
}

/**
 * @brief Construct a new GramatronGenerateMutator::GramatronGenerateMutator object
 *
 * @param name the name of the module
 */
GramatronGenerateMutator::GramatronGenerateMutator(std::string name) :
    MutatorModule(name)
{

}
/**
 * @brief Destroy the GramatronGenerateMutator::GramatronGenerateMutator object
 * 
 */
GramatronGenerateMutator::~GramatronGenerateMutator()
{

}

/**
 * @brief Registers storage needs
 * This class uses only the "TEST_CASE" and the "TEST_CASE_AUT" keys
 * 
 * @param registry 
 */
void GramatronGenerateMutator::registerStorageNeeds(StorageRegistry& registry)
{
    testCaseKey = registry.registerKey("TEST_CASE", StorageRegistry::BUFFER, StorageRegistry::WRITE_ONLY);
    autRepKey = registry.registerKey("TEST_CASE_AUT", StorageRegistry::BUFFER, StorageRegistry::WRITE_ONLY);
}


/**
 * @brief Creates a new test case by mutating the base entry
 * 
 * @param storage reference to storage
 * @param baseEntry the base entry to use for mutation (this is ignored by this mutator)
 * @return StorageEntry*
 */
StorageEntry* GramatronGenerateMutator::createTestCase(StorageModule& storage, StorageEntry* baseEntry)
{
    //Note: baseEntry is ignored by this mutator

    StorageEntry* newEntry = storage.createNewEntry();

    generate(newEntry);

    return newEntry;
}

/**
 * @brief Generate a new random walk from the PDA.
 *
 * @param newEntry the new entry to provide a test case for
 * @param storage storage access need for benchmarking
 */
void GramatronGenerateMutator::generate(StorageEntry* newEntry)
{
    Array* mutated;

    //We set input to null and state to 0 so that we do a brand new walk over the PDA from the initial state
    mutated = gen_input(pda, NULL, 0);

    //store the automaton representation in storage
    storeTestCase(newEntry,mutated, testCaseKey, autRepKey);
}
