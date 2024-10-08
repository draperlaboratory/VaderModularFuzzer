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

using namespace vmf;

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
    rand = VmfRand::getInstance();
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
 * 
 * @param registry 
 */
void GramatronRandomMutator::registerStorageNeeds(StorageRegistry& registry)
{
    //This module does not register for a test case buffer key, because mutators are told which buffer to write in storage 
    //by the input generator that calls them

    autRepKey = registry.registerKey("TEST_CASE_AUT", StorageRegistry::BUFFER, StorageRegistry::READ_WRITE);
}

/**
 * @brief Creates a new test case by mutating the base entry
 * 
 * @param storage reference to storage
 * @param baseEntry the base entry to use for mutation
 * @param newEntry the new entry to write to
 * @param testCaseKey the field to write to in the new entry
 * @throws RuntimeException if the baseEntry has an empty test case buffer.
 */
void GramatronRandomMutator::mutateTestCase(StorageModule& storage, StorageEntry* baseEntry, StorageEntry* newEntry, int testCaseKey)
{
    int size = baseEntry->getBufferSize(autRepKey);
    char* buffer = baseEntry->getBufferPointer(autRepKey);

    if(size <= 0)
    {
        throw RuntimeException("GramatronMutator mutate called with zero sized buffer", RuntimeException::USAGE_ERROR);
    }

    random(newEntry, buffer, testCaseKey);

}

/**
 * @brief Pick a random symbol in the test case to do a new random walk from in the PDA.
 *
 * @param newEntry the new entry to provide a test case for
 * @param buffer the base test case buffer to mutate from
 * @param testCaseKey the field to write to
 */
void GramatronRandomMutator::random(StorageEntry* newEntry, char* buffer, int testCaseKey)
{
    Array* input = read_input(pda->state_ptr(),buffer);

    terminal *term_ptr;
    Array* mutated;
    Array* sliced;

    // Get offset at which to generate new input and slice it
    int idx = rand -> randBelow(input->used);
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
