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
 *
 * This file includes software from the Gramatron project,
 * https://github.com/HexHive/Gramatron/
 * Copyright (c) 2021 HexHive Group, Prashast Srivastava, Mathias Payer
 * Gramatron software licensed under the Apache License, Version 2.0
 * @license Apache-2.0 https://spdx.org/licenses/Apache-2.0.html
 * ===========================================================================*/
#include "GramatronSpliceMutator.hpp"
#include <random>
#include <algorithm>
#include <unistd.h>

using namespace vader;

#include "ModuleFactory.hpp"
REGISTER_MODULE(GramatronSpliceMutator);

/**
 * @brief Builder method to support the ModuleFactory
 * Constructs an instance of this class
 * @return Module* 
 */
Module* GramatronSpliceMutator::build(std::string name)
{
    return new GramatronSpliceMutator(name);
}

/**
 * @brief Initialization method
 * 
 * @param config 
 */
void GramatronSpliceMutator::init(ConfigInterface& config)
{
    pda = PDA::GetInstance();
}

/**
 * @brief Construct a new GramatronSpliceMutator::GramatronSpliceMutator object
 * 
 * @param name the name of the module
 */
GramatronSpliceMutator::GramatronSpliceMutator(std::string name) :
    MutatorModule(name)
{

}
/**
 * @brief Destroy the GramatronSpliceMutator::GramatronSpliceMutator object
 * 
 */
GramatronSpliceMutator::~GramatronSpliceMutator()
{

}

/**
 * @brief Registers storage needs
 * This class uses only the "TEST_CASE" and "TEST_CASE_AUT" keys,
 * and the "RAN_SUCCESSFULLY" tag
 * 
 * @param registry 
 */
void GramatronSpliceMutator::registerStorageNeeds(StorageRegistry& registry)
{
    testCaseKey = registry.registerKey("TEST_CASE", StorageRegistry::BUFFER, StorageRegistry::WRITE_ONLY);
    autRepKey = registry.registerKey("TEST_CASE_AUT", StorageRegistry::BUFFER, StorageRegistry::READ_WRITE);
    normalTag = registry.registerTag("RAN_SUCCESSFULLY", StorageRegistry::READ_ONLY);
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
StorageEntry* GramatronSpliceMutator::createTestCase(StorageModule& storage, StorageEntry* baseEntry)
{
    int size = baseEntry->getBufferSize(autRepKey);

    if(size <= 0)
    {
        throw RuntimeException("GramatronSpliceMutator mutate called with zero sized buffer", RuntimeException::USAGE_ERROR);
    }

    StorageEntry* newEntry = storage.createNewEntry();

    splice(newEntry, baseEntry, storage);

    return newEntry;
}

/**
 * @brief Pick two test cases and attempt to splice them together at an appropriate yet randomly chosen point.
 *
 * @param newEntry the new entry to provide a test case for
 * @param baseEntry the base test case entry to mutate from
 * @param storage storage access need for benchmarking
 */
void GramatronSpliceMutator::splice(StorageEntry* newEntry, StorageEntry* baseEntry, StorageModule& storage)
{
    // get information for base test case that will be spliced
    char* buffer = baseEntry->getBufferPointer(autRepKey);
    int baseID = baseEntry->getID();

    // get a random second test case that will be spliced
    StorageEntry* secondEntry = nullptr;
    int randIndex = 0;

    std::unique_ptr<Iterator> entries = storage.getEntriesByTag(normalTag);
    int maxIndex = entries->getSize();
    // make sure that random case is not the same as the base case
    int secondID = baseID;
    int count=0;
    while((secondID == baseID)&&(count<3))
    {
        //switched from afl_rand_below
        randIndex = rand() % maxIndex;
        secondEntry = entries->setIndexTo(randIndex);
        secondID = secondEntry->getID();
        count++; //We need to prevent an infinite loop in case there are only a few test cases in the queue
    }
    char* secondBuffer = secondEntry->getBufferPointer(autRepKey);

    Array* originput = read_input(pda->state_ptr(),buffer);

    Array* splicecand = read_input(pda->state_ptr(),secondBuffer);

    // logic from gramatron splice
    // Create statemap for the fuzz candidate
    IdxMap_new* statemap_ptr;
    terminal* term_ptr;
    int state;

    IdxMap_new* statemap_start = (IdxMap_new*)malloc(sizeof(IdxMap_new)*pda->num_states());
    for (int x = 0; x < pda->num_states(); x++) {
        statemap_ptr = & statemap_start[x];
        utarray_new(statemap_ptr->nums, &ut_int_icd);
    }
    size_t offset = 0;
    while(offset < originput->used) {
        term_ptr = & originput->start[offset];
        state = term_ptr->state;
        statemap_ptr = &statemap_start[state];
        utarray_push_back(statemap_ptr->nums, &offset);
        offset += 1;
    }

    Array* mutated = performSpliceOne(originput,statemap_start,splicecand);

    storeTestCase(newEntry, mutated, testCaseKey, autRepKey);

    for(int x = 0; x < pda->num_states(); x++) {
        utarray_free(statemap_start[x].nums);
    }
    free(statemap_start);
    free(originput->start);
    free(originput);
    free(splicecand->start);
    free(splicecand);
}

/* --
 * Start of code copied from Gramatron, source file
 * https://github.com/HexHive/Gramatron/blob/main/src/gramfuzz-mutator/gramfuzz-mutators.c
  -- */
UT_icd intpair_icd = {sizeof(intpair_t), NULL, NULL, NULL};

/**
 * @brief Tries to perform splice operation between two automaton walks
 *
 * @param originput the first PDA walk to get a slice from
 * @param statemap_orig data structure to locate appropriate splice points in the PDA walk
 * @param splicecand the second PDA walk to get a slice from
 */
Array* GramatronSpliceMutator::performSpliceOne(Array* originput, IdxMap_new* statemap_orig, Array* splicecand) {
    UT_array* stateptr, *pairs;
    intpair_t ip;
    intpair_t *cand;

    terminal* term_ptr;
    Array* prefix;

    // Initialize the dynamic holding the splice indice pairs
    utarray_new(pairs, &intpair_icd);

    // Iterate through the splice candidate identifying potential splice points
    // and pushing pair (orig_idx, splice_idx) to a dynamic array
    for(size_t x = 0; x < splicecand->used; x++ ) {
        term_ptr = & splicecand->start[x];
        stateptr = statemap_orig[term_ptr->state].nums;

        int length = utarray_len(stateptr);

        if (length) {
            int* splice_idx = (int *)utarray_eltptr(stateptr, (unsigned int)(rand() % length));

            ip.orig_idx = *splice_idx;
            ip.splice_idx = x;
            utarray_push_back(pairs, &ip);
        }
    }

    // Pick a random pair
    int length = utarray_len(pairs);
    cand = (intpair_t *)utarray_eltptr(pairs, (unsigned int)(rand() % length));

    // Perform the splicing
    prefix = slice(originput, cand->orig_idx);
    Array* spliced = spliceGF(prefix, splicecand, cand->splice_idx);

    utarray_free(pairs);

    return spliced;
}
/* -- End of code copied from Gramatron */