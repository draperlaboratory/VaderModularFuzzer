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
#include "GramatronRandomMutator.hpp"
#include <random>
#include <algorithm>
#include <unistd.h>

using namespace vader;

#include "ModuleFactory.hpp"
REGISTER_MODULE(GramatronRandomMutator);

/**
 * @brief Builder method to support the ModuleFactory
 * Constructs an instance of this class
 * @return Module* 
 */
Module* GramatronRandomMutator::build(std::string name)
{
    return new GramatronRandomMutator(name);
}

/**
 * @brief Initialization method
 * 
 * @param config 
 */
void GramatronRandomMutator::init(ConfigInterface& config)
{
    pda = PDA::GetInstance();
}

/**
 * @brief Construct a new GramatronRandomMutator::GramatronRandomMutator object
 * 
 * @param name the name of the module
 */
GramatronRandomMutator::GramatronRandomMutator(std::string name) :
    MutatorModule(name)
{

}
/**
 * @brief Destroy the GramatronRandomMutator::GramatronRandomMutator object
 * 
 */
GramatronRandomMutator::~GramatronRandomMutator()
{

}

/**
 * @brief Registers storage needs
 * This class uses only the "TEST_CASE" and "TEST_CASE_AUT" keys
 * 
 * @param registry 
 */
void GramatronRandomMutator::registerStorageNeeds(StorageRegistry& registry)
{
    testCaseKey = registry.registerKey("TEST_CASE", StorageRegistry::BUFFER, StorageRegistry::WRITE_ONLY);
    autRepKey = registry.registerKey("TEST_CASE_AUT", StorageRegistry::BUFFER, StorageRegistry::READ_WRITE);
}

/**
 * @brief Creates a new test case by mutating the base entry
 * 
 * @param storage reference to storage
 * @param baseEntry the base entry to use for mutation
 * @return StorageEntry* 
 * @throws RuntimeException if an invalid algorithm type is provided, which should not be possible,
 * or if the baseEntry has an empty test case buffer.
 */
StorageEntry* GramatronRandomMutator::createTestCase(StorageModule& storage, StorageEntry* baseEntry)
{
    int size = baseEntry->getBufferSize(autRepKey);
    char* buffer = baseEntry->getBufferPointer(autRepKey);

    if(size <= 0)
    {
        throw RuntimeException("GramatronMutator mutate called with zero sized buffer", RuntimeException::USAGE_ERROR);
    }

    StorageEntry* newEntry = storage.createNewEntry();

    random(newEntry, buffer);

    return newEntry;
}

/**
 * @brief Pick a random symbol in the test case to do a new random walk from in the PDA.
 *
 * @param newEntry the new entry to provide a test case for
 * @param buffer the base test case buffer to mutate from
 */
void GramatronRandomMutator::random(StorageEntry* newEntry, char* buffer)
{
    Array* input = read_input(pda->state_ptr(),buffer);

    terminal *term_ptr;
    Array* mutated;
    Array* sliced;

    // Get offset at which to generate new input and slice it
    int idx = rand() % input->used;
    sliced = slice(input, idx);

    // Reset current state to that of the slice's last member
    term_ptr = & input->start[idx];
    int curr_state = term_ptr->state;

    // Set the next available cell to the one adjacent to this chosen point
    mutated = gen_input(pda, sliced, curr_state);

    storeTestCase(newEntry, mutated, testCaseKey, autRepKey);

    free(input->start);
    free(input);
}
