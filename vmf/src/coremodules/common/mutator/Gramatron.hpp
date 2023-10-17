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

#pragma once

#include "stdlib.h"
#include "string"
#include "cstring"
#include "fstream"
#include "sstream"
#include "utarray.h"
#include "unistd.h"

/* --
 * Start of code copied from Gramatron, source file
 * https://github.com/HexHive/Gramatron/blob/main/src/include_AFL/gramfuzzer.h
  -- */
#define INIT_SIZE 100
#define RECUR_THRESHOLD 6

/**
 * @brief Struct to define one transition function between states in a PDA
 *
 */
typedef struct trigger {
    char *id; ///< ID of transition function in PDA
    int dest; ///< Destination PDA state of the transition function
    char *term; ///< Pointer to char array of string which causes this transition function to be taken
    size_t term_len; ///< Length of term
} trigger;

/**
 * @brief Struct to define one state in a PDA
 *
 */
typedef struct pdaState{
    int stateName; ///< State ID
    int trigger_len; ///< Number of transition functions from this state
    trigger *ptr; ///< pointer to the first trigger in the list
} pdaState;

/**
 * @brief Struct to define one state used in a PDA walk
 *
 */
typedef struct terminal {
    int state; ///< State ID
    int trigger_idx; ///< The index into the list of transition functions which transition to this state
    size_t symbol_len; ///< Length of the represented state in terms of characters
    char *symbol; ///< A pointer to the symbol char array
} terminal;

/**
 * @brief Struct to define a PDA walk
 *
 */
typedef struct {
    size_t used; ///< The number of used entries
    size_t size; ///< The number of states in the walk
    size_t inputlen; ///< The cumulative length of the symbols added to the input over this walk
    terminal *start; ///< Pointer to the front of the array of terminals in this walk
} Array;

/*****************
/ DYNAMIC ARRAY FOR STATEMAPS/RECURSION MAPS
*****************/

/**
 * @brief Struct to make splice and recursion mutators more efficient by one layer of indirection
 *
 */
typedef struct {
    UT_array *nums; ///< Pointer to a dynamic array, a contiguous memory region into which the states in the test case are copied
} IdxMap_new;

/**
 * @brief Struct to help with splice in defining potential splice points in a test case (works with the state map)
 *
 */
typedef struct {
    int orig_idx; ///< State index for the splice to occur in the first input selected
    int splice_idx; ///< State index for splice to occur in the candidate splice test case
} intpair_t;
/* -- End of code copied from Gramatron */

void initArray(Array*, size_t);
void insertArray(Array*, int, char*, size_t, int);

Array* slice(Array* input, int idx);
Array* carve(Array* input, int start, int end);
void concatPrefixFeature(Array* prefix, Array* feature);

Array* spliceGF(Array* orig, Array* toSplice, int idx);

char* unparse_walk(Array*);
void write_input(Array* input, char* fn);
Array* read_input(pdaState* pda, char* buffer);

void getTwoIndices(UT_array* recur, int recurlen, int* firstIdx, int* secondIdx);
void swap (int *a, int *b);