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
#include "GramatronRecursiveMutator.hpp"
#include <random>
#include <algorithm>
#include <unistd.h>

using namespace vmf;

#include "ModuleFactory.hpp"
REGISTER_MODULE(GramatronRecursiveMutator);

/**
 * @brief Builder method to support the ModuleFactory
 * Constructs an instance of this class
 * @return Module* 
 */
Module* GramatronRecursiveMutator::build(std::string name)
{
    return new GramatronRecursiveMutator(name);
}

/**
 * @brief Initialization method
 * 
 * @param config 
 */
void GramatronRecursiveMutator::init(ConfigInterface& config)
{
    pda = PDA::GetInstance();
}

/**
 * @brief Construct a new GramatronRecursiveMutator::GramatronRecursiveMutator object
 *
 * @param name the name of the module
 */
GramatronRecursiveMutator::GramatronRecursiveMutator(std::string name) :
    MutatorModule(name)
{

}
/**
 * @brief Destroy the GramatronRecursiveMutator::GramatronRecursiveMutator object
 * 
 */
GramatronRecursiveMutator::~GramatronRecursiveMutator()
{

}

/**
 * @brief Registers storage needs
 * 
 * @param registry 
 */
void GramatronRecursiveMutator::registerStorageNeeds(StorageRegistry& registry)
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
void GramatronRecursiveMutator::mutateTestCase(StorageModule& storage, StorageEntry* baseEntry, StorageEntry* newEntry, int testCaseKey)
{
    int size = baseEntry->getBufferSize(autRepKey);
    char* buffer = baseEntry->getBufferPointer(autRepKey);

    if(size <= 0)
    {
        throw RuntimeException("GramatronMutator mutate called with zero sized buffer", RuntimeException::USAGE_ERROR);
    }

    recursive(newEntry, buffer, testCaseKey);

}

/**
 * @brief Pick a random symbol in the test case to do a new random walk from in the PDA.
 *
 * @param newEntry the new entry to provide a test case for
 * @param buffer the base test case buffer to mutate from
 * @param testCaseKey the field to write to in the new entry
 */
void GramatronRecursiveMutator::random(StorageEntry* newEntry, char* buffer, int testCaseKey)
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

/**
 * @brief Generates new test case by picking a recursive feature and expanding it up to RECUR_THRESHOLD times
 *
 * @param newEntry the new entry to provide a test case for
 * @param buffer the base test case buffer to mutate from
 * @param testCaseKey the field to write to in the new entry
 */
void GramatronRecursiveMutator::recursive(StorageEntry* newEntry, char* buffer, int testCaseKey)
{
    Array* input = read_input(pda->state_ptr(),buffer);
    IdxMap_new* statemap_ptr ;
    terminal *term_ptr;
    int state;
    int recurlen = 0;

    Array* mutated;

    IdxMap_new* statemap_start = (IdxMap_new*)malloc(sizeof(IdxMap_new)*pda->num_states());
    for (int x = 0; x < pda->num_states(); x++) {
        statemap_ptr = & statemap_start[x];
        utarray_new(statemap_ptr->nums, &ut_int_icd);
    }
    size_t offset = 0;
    while(offset < input->used) {
        term_ptr = & input->start[offset];
        state = term_ptr->state;
        statemap_ptr = &statemap_start[state];
        utarray_push_back(statemap_ptr->nums, &offset);
        offset += 1;
    }

    // Create recursive feature map (if it exists)
    UT_array **recurIdx = (UT_array**)malloc(sizeof(UT_array*)*pda->num_states());
    // Retrieve the duplicated states
    offset = 0;
    while(offset < (size_t)pda->num_states()) {
        statemap_ptr = &statemap_start[offset];
        int length = utarray_len(statemap_ptr->nums);
        if (length >= 2) {
            recurIdx[recurlen] = statemap_ptr->nums;
            recurlen += 1;
        }
        offset += 1;
    }

    if(recurlen > 0) {
        mutated = doMult(input, recurIdx, recurlen);

        storeTestCase(newEntry, mutated, testCaseKey, autRepKey);

    } else {
        //Do a random mutation instead since there are no recursive features in this test case
        GramatronRecursiveMutator::random(newEntry, buffer, testCaseKey);
    }

    for(int x = 0; x < pda->num_states(); x++) {
        utarray_free(statemap_start[x].nums);
    }
    free(statemap_start);
    free(recurIdx);
    free(input->start);
    free(input);
}

/* --
 * Start of code copied from Gramatron, source file
 * https://github.com/HexHive/Gramatron/blob/main/src/gramfuzz-mutator/gramfuzz-mutators.c
  -- */
/**
 * @brief Does recursive mutations
 *
 * @param input the PDA walk to be mutated
 * @param recur recursive feature map for this input
 * @param recurlen number of recursive features
 */
Array* GramatronRecursiveMutator::doMult(Array* input, UT_array** recur, int recurlen) {
    //select one of the recursive features
    int idx = rand() % (recurlen);
    UT_array* recurMap = recur[idx];

    Array* prefix;
    Array* feature;

    // Choose two indices to get the recursive feature
    int recurIndices = utarray_len(recurMap);
    int firstIdx = 0;
    int secondIdx = 0;
    getTwoIndices(recurMap, recurIndices, &firstIdx, &secondIdx);

    // Perform the recursive mut, the slice gets the part of the test case which will not be mutated
    prefix = slice(input, firstIdx);
    if (firstIdx < secondIdx) {
        feature = carve(input, firstIdx, secondIdx);
    }
    else {
        feature = carve(input, secondIdx, firstIdx);
    }
    concatPrefixFeature(prefix, feature);

    // GC allocated structures
    free(feature->start);
    free(feature);
    return spliceGF(prefix, input, secondIdx);
}

/**
 * @brief Generate a new random walk from the PDA.
 *
 * @param recur the recursive feature map
 * @param recurlen the number of recursive features
 * @param firstIdx this will be set to the end of the portion of the test case to leave alone
 * @param secondIdx this will be set to the end of the recursive feature to pull out and mutate with
 */
void GramatronRecursiveMutator::getTwoIndices(UT_array* recur, int recurlen, int* firstIdx, int* secondIdx) {
    int ArrayRecurIndices[recurlen];
    int offset = 0, *p;
    // Unroll into an array
    for (p=(int*)utarray_front(recur); p!= NULL; p=(int*)utarray_next(recur,p)) {
        ArrayRecurIndices[offset] = *p;
        offset += 1;
    }

    /*Source: https://www.geeksforgeeks.org/shuffle-a-given-array-using-fisher-yates-shuffle-algorithm/ */
    // This shuffles the recursive sub walk to get two random indices so our selection of a recursive feature is done at random
    for (int i = offset-1; i > 0; i--) {
        // Pick a random index from 0 to i
        int j = rand() % (i+1);

        // Swap arr[i] with the element at random index
        swap(&ArrayRecurIndices[i], &ArrayRecurIndices[j]);
    }

    // Get the first two indices
    *firstIdx = ArrayRecurIndices[0];
    *secondIdx = ArrayRecurIndices[1];

}

/**
 * @brief Switch pointer values
 *
 * @param a the first pointer
 * @param b the second pointer
 */
void GramatronRecursiveMutator::swap (int *a, int *b)
{
    int temp = *a;
    *a = *b;
    *b = temp;
}
/* -- End of code copied from Gramatron */
