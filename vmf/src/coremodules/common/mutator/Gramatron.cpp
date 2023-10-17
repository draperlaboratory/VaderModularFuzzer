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
#include "Gramatron.hpp"
#include "Logging.hpp"

/* --
 * Start of code copied from Gramatron, source file
 * https://github.com/HexHive/Gramatron/blob/main/src/gramfuzz-mutator/gramfuzz-helpers.c
 * https://github.com/HexHive/Gramatron/blob/main/src/gramfuzz-mutator/gramfuzz-util.c
  -- */
/**
 * @brief Slices from beginning of walk until idx
 *
 * @param input the PDA walk to slice
 * @param idx the index to stop at for our slice
 */
Array* slice(Array* input, int idx) {
    terminal* origptr;

    Array* sliced = (Array *)malloc(sizeof(Array));
    initArray(sliced, input->size);
    // Populate dynamic array members
    if (idx == 0) {
        return sliced;
    }
    for(int x = 0; x < idx; x++) {
        origptr = & input->start[x];
        insertArray(sliced, origptr->state, origptr->symbol, origptr->symbol_len, origptr->trigger_idx);
    }
    return sliced;
}

/**
 * @brief Carves out a sub walk with `start` included and `end` excluded
 *
 * @param input PDA walk to carve feature out of
 * @param start recursive feature beginning index
 * @param end recursive feature ending index
 */
Array* carve(Array* input, int start, int end) {
    terminal* origptr;

    Array* sliced = (Array *)malloc(sizeof(Array));
    initArray(sliced, input->size);
    for(int x = start; x < end; x++) {
        origptr = & input->start[x];
        insertArray(sliced, origptr->state, origptr->symbol, origptr->symbol_len, origptr->trigger_idx);
    }
    return sliced;
}

/**
 * @brief Concatenates a recursive feature to the input up to RECUR_THRESHOLD times
 *
 * @param prefix PDA walk to insert features after
 * @param feature recursive feature to insert into the test case
 */
void concatPrefixFeature(Array* prefix, Array* feature) {
    //TODO(VADER-1049): Currently we have hardcoded the multiplication threshold for adding
    // the recursive feature. Might want to fix it to choose a random number upper
    // bounded by a static value instead.
    terminal* featureptr;
    int len = rand() % RECUR_THRESHOLD;
    for (int x = 0; x < len; x++) {
        for (size_t y = 0; y < feature->used; y++) {
            featureptr = & feature->start[y];
            insertArray(prefix, featureptr->state, featureptr->symbol, featureptr->symbol_len, featureptr->trigger_idx);
        }
    }
}

/**
 * @brief Initialize the PDA walk representation
 *
 * @param a the new walk pointer
 * @param initialSize the max number of states we expect for the walk
 */
void initArray(Array* a, size_t initialSize) {
    a->start = (terminal *)calloc(1, sizeof(terminal) * initialSize);
    a->used = 0;
    a->size = initialSize;
    a->inputlen = 0;
}

/**
 * @brief Splice two portions of PDA walks together into one walk
 *
 * @param orig the PDA walk to append to
 * @param toSplice the second PDA walk which is appended to orig
 * @param idx the start point in the splice candidate to iterate from
 */
Array* spliceGF(Array* orig, Array* toSplice, int idx) {
    terminal* toSplicePtr;

    // Iterate through the splice candidate from the `idx` until end
    for(size_t x = idx; x < toSplice->used; x++) {
        toSplicePtr = & toSplice->start[x];
        //insert next state into orig
        insertArray(orig, toSplicePtr->state, toSplicePtr->symbol, toSplicePtr->symbol_len, toSplicePtr->trigger_idx);
    }
    return orig;
}

/**
 * @brief Insert a state and chosen transition function artifacts from that state into the PDA walk representation
 *
 * @param a the PDA walk pointer at its current state
 * @param state the state we are currently in for this step of the PDA walk
 * @param symbol the char buffer which this state transition pushes/pops from the stack
 * @param symbol_len the length of the symbol char buffer
 * @param trigger_idx trigger index from the list of transition functions from the current state
 */
void insertArray(Array *a, int state, char* symbol, size_t symbol_len, int trigger_idx) {
    // a->used is the number of used entries, because a->array[a->used++] updates a->used only *after* the array has been accessed.
    // Therefore a->used can go up to a->size
    terminal *term_ptr;
    if (a->used == a->size) {
        a->size = a->size * sizeof(terminal);
        a->start = (terminal *)realloc(a->start, a->size * sizeof(terminal));
    }
    // Add the element
    term_ptr = & a->start[a->used];
    term_ptr->state = state;
    term_ptr->symbol = symbol;
    term_ptr->symbol_len = symbol_len;
    term_ptr->trigger_idx = trigger_idx;

    // Increment the pointer
    a->used += 1;
    a->inputlen += symbol_len;

}

/**
 * @brief Insert a state and chosen transition function artifacts from that state into the PDA walk representation
 *
 * Gramatron C implementation used u8 type for return type, changed to char when converting from C to C++
 *
 * @param input the PDA walk representation which we are unparsing into a char buffer
 */
char* unparse_walk(Array* input) {
    terminal* term_ptr;
    size_t offset = 0;
    char *unparsed = (char*)malloc(input->inputlen + 1);
    term_ptr = & input->start[offset];
    std::strcpy(unparsed, term_ptr->symbol);
    offset += 1;
    while (offset < input->used) {
        term_ptr = & input->start[offset];
        std::strcat(unparsed, term_ptr->symbol);
        offset += 1;
    }
    return unparsed;
}
/* -- End of code copied from Gramatron */

/**
 * @brief Dump the input PDA representation into a file. Currently not in use.
 *
 * @param input the PDA walk representation
 * @param fn the file name in a char buffer
 */
void write_input(Array* input, char* fn) {
    FILE *fp;
    // If file already exists, then skip creating the file
    if (access (fn, F_OK) != -1) {
        return;
    }

    fp = fopen(fn, "wbx+");
    // If the input has already been flushed, then skip silently
    // This matters for the AFL++ implementation but likely not for VMF
    if (fp == NULL) {
        LOG_WARNING << "File (" << fn << ") could not be opened, exiting";
        exit(1);
    }

    // Write the length parameters
    fwrite(&input->used, sizeof(size_t), 1, fp);
    fwrite(&input->size, sizeof(size_t), 1, fp);
    fwrite(&input->inputlen, sizeof(size_t), 1, fp);

    // Write the dynamic array to file
    fwrite(input->start, input->size*sizeof(terminal), 1, fp);
    fclose(fp);
}

/**
 * @brief Read the input representation into memory
 *
 * @param pda pointer to the first state in the PDA
 * @param buffer the data to reconstruct the automata walk structure from
 */
Array* read_input(pdaState* pda, char* buffer) {
    terminal *term;
    pdaState *state_ptr;
    trigger *trigger;
    int trigger_idx;
    Array* input = (Array*)calloc(1, sizeof(Array));

    // Read the length parameters
    size_t src_index = 0;
    memcpy(&input->used,&buffer[src_index],sizeof(size_t));
    src_index += sizeof(size_t);
    memcpy(&input->size,&buffer[src_index],sizeof(size_t));
    src_index += sizeof(size_t);
    memcpy(&input->inputlen,&buffer[src_index],sizeof(size_t));
    src_index += sizeof(size_t);

    terminal *start_ptr = (terminal*)calloc(input->size, sizeof(terminal));

    // Read the dynamic array to memory
    memcpy(start_ptr,&buffer[src_index],input->size*sizeof(terminal));

    // Update the pointers to the terminals since they would have changed
    size_t idx = 0;
    while (idx < input->used) {
        term = & start_ptr[idx];
        // Find the state
        state_ptr = pda + term->state;
        // Find the trigger and update the terminal address
        trigger_idx = term->trigger_idx;
        trigger = (state_ptr->ptr) + trigger_idx;
        term->symbol = trigger->term;
        idx += 1;
    }

    input->start = start_ptr;

    return input;
}
