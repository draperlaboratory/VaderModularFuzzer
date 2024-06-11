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
#include "GramatronHelpers.hpp"

using namespace vmf;

/**
 * @brief Generates/mutates test case by random walk over the PDA
 *
 * @param pda_s pointer to the pushdown automata singleton
 * @param input the test case we will be mutating
 * @param curr_state the state we want to do a random walk from
 */
Array* vmf::gen_input(PDA *pda_s, Array* input, int curr_state) {
    pdaState* state_ptr;
    trigger* trigger_ptr;

    int randval;

    // Generating an input for the first time
    // (vs doing a random walk from a terminal of an existing test case)
    if (input == NULL) {
        input = (Array *)calloc(1, sizeof(Array));
        initArray(input, INIT_SIZE);
        curr_state = pda_s->init_state();
    }

    //The final state is not inserted into the walk
    while (curr_state != pda_s->final_state()) {
        // Retrieving the state from the pda depending on if this is a new input or a random walk from an old input
        state_ptr = pda_s->state_ptr() + curr_state;

        // Get a random trigger based on the number of triggers/transition functions out of the automata current state
        randval = rand() % (state_ptr->trigger_len);
        trigger_ptr = (state_ptr->ptr) + randval;

        // Insert into the dynamic array (essentially the PDA walk)
        insertArray(input, curr_state, trigger_ptr->term, trigger_ptr->term_len, randval);

        //update current state to the destination automata state of the chosen transition function
        curr_state = trigger_ptr->dest;
    }

    //return PDA representation (pointer to first PDA state of states and transition functions traversed)
    return input;
}

/**
 * @brief Creates new PDA based test cases by random walk over the PDA
 *
 * @param storage storage module to insert newly generated test cases
 * @param testCaseKey key to string field for test case
 * @param autRepKey key to automata representation buffer for test case
 * @param num_testcases the number of test cases to generate
 */
void vmf::createNewTestCasesFromPDA(StorageModule& storage, int testCaseKey, int autRepKey, int num_testcases) {
    //get our PDA singleton
    PDA *pda_s = PDA::GetInstance();

    for(int i = 0; i < num_testcases; i++) {
        int size = 0;

        //generate new input
        Array *input = gen_input(pda_s,NULL, 0);

        size = input->inputlen;

        if (0 == size) {
            LOG_INFO << "Warning: ignoring input file of size 0.";
            continue;
        }

        StorageEntry *newEntry = storage.createNewEntry();

        storeTestCase(newEntry,input,testCaseKey,autRepKey);
    }
}

/**
 * @brief Creates new PDA based test cases by random walk over the PDA
 *
 * @param newEntry storage entry to insert newly generated test case data
 * @param input PDA walk to store
 * @param testCaseKey key to string field for test case
 * @param autRepKey key to automata representation buffer for test case
 */
void vmf::storeTestCase(StorageEntry* newEntry, Array* input, int testCaseKey, int autRepKey){
    int size = input->inputlen;

    char* buff = newEntry->allocateBuffer(testCaseKey, size);

    int aut_size = input->size*sizeof(terminal) + 3*sizeof(size_t);
    char* aut_buff = newEntry->allocateBuffer(autRepKey,aut_size);


    char *unparsed_input = unparse_walk(input);

    //read into the buffer
    memcpy(buff,unparsed_input,size);

    size_t dest_index = 0;
    memcpy(&aut_buff[dest_index], &input->used, sizeof(size_t));
    dest_index += sizeof(size_t);
    memcpy(&aut_buff[dest_index], &input->size, sizeof(size_t));
    dest_index += sizeof(size_t);
    memcpy(&aut_buff[dest_index], &input->inputlen, sizeof(size_t));
    dest_index += sizeof(size_t);

    memcpy(&aut_buff[dest_index], input->start, input->size*sizeof(terminal));

    free(input->start);
    free(input);
    free(unparsed_input);
}


