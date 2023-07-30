/* =============================================================================
 * Vader Modular Fuzzer (VMF)
 * Copyright (c) 2021-2023 The Charles Stark Draper Laboratory, Inc.
 * <vader@draper.com>
 *  
 * Effort sponsored by the U.S. Government under Other Transaction number
 * W9124P-19-9-0001 between AMTC and the Government. The U.S. Government
 * Is authorized to reproduce and distribute reprints for Governmental purposes
 * notwithstanding any copyright notation thereon.
 *  
 * The views and conclusions contained herein are those of the authors and
 * should not be interpreted as necessarily representing the official policies
 * or endorsements, either expressed or implied, of the U.S. Government.
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
/*****
 * The following includes code copied from the LibAFL_Legacy repository.
 * 
 *       american fuzzy lop++ - fuzzer header
 *  ------------------------------------
 *  Originally written by Michal Zalewski
 *  Now maintained by Marc Heuse <mh@mh-sec.de>,
 *                    Heiko Eißfeldt <heiko.eissfeldt@hexco.de>,
 *                    Andrea Fioraldi <andreafioraldi@gmail.com>,
 *                    Dominik Maier <mail@dmnk.co>
 *  Copyright 2016, 2017 Google Inc. All rights reserved.
 *  Copyright 2019-2020 AFLplusplus Project. All rights reserved.
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at:
 *    http://www.apache.org/licenses/LICENSE-2.0
 *  This is the Library based on AFL++ which can be used to build
 *  customized fuzzers for a specific target while taking advantage of
 *  a lot of features that AFL++ already provides.
 */

#include "AFLCloneMutator.hpp"
#include "AFLDeleteMutator.hpp" //For static choose_block_len method
#include "RuntimeException.hpp"
#include <random>
#include <algorithm>

using namespace vader;

#include "ModuleFactory.hpp"
REGISTER_MODULE(AFLCloneMutator);

/**
 * @brief Builder method to support the ModuleFactory
 * Constructs an instance of this class
 * @return Module* 
 */
Module* AFLCloneMutator::build(std::string name)
{
    return new AFLCloneMutator(name);
}

/**
 * @brief Initialization method
 * 
 * @param config 
 */
void AFLCloneMutator::init(ConfigInterface& config)
{

}

/**
 * @brief Construct a new AFLCloneMutator::AFLCloneMutator object
 * 
 * @param name the name of the module
 */
AFLCloneMutator::AFLCloneMutator(std::string name) :
    MutatorModule(name)
{
    afl_rand_init(&rand);
}

/**
 * @brief Destroy the AFLCloneMutator::AFLCloneMutator object
 * 
 */
AFLCloneMutator::~AFLCloneMutator()
{

}

/**
 * @brief Registers storage needs
 * This class uses only the "TEST_CASE" key
 * 
 * @param registry 
 */
void AFLCloneMutator::registerStorageNeeds(StorageRegistry& registry)
{
    testCaseKey = registry.registerKey("TEST_CASE", StorageRegistry::BUFFER, StorageRegistry::READ_WRITE);
}
 
StorageEntry* AFLCloneMutator::createTestCase(StorageModule& storage, StorageEntry* baseEntry)
{

    int size = baseEntry->getBufferSize(testCaseKey);
    char* buffer = baseEntry->getBufferPointer(testCaseKey);

    if(size <= 0)
    {
        throw RuntimeException("AFLCloneMutator mutate called with zero sized buffer", RuntimeException::USAGE_ERROR);
    }

    StorageEntry* newEntry = storage.createNewEntry();

    //The variable actually_clone determines which strategy is used.
    int actually_clone = afl_rand_below(&rand, 4);
    int clone_from;
    int clone_len;
    int clone_to = afl_rand_below(&rand, size);

    if (actually_clone) {
        //Clone a small block of the original data

        clone_len = AFLDeleteMutator::choose_block_len(&rand, size);
        clone_from = afl_rand_below(&rand, size - clone_len + 1);

        int newSize = clone_len + size;
        char* newBuff = newEntry->allocateBuffer(testCaseKey, newSize);

        //Copies a random number of bytes (clone_to) from the original buffer
        memcpy((void*)newBuff, (void*)buffer, clone_to);

        //Insert some bytes in the middle (cloning from part of the original buffer)
        memcpy(newBuff + clone_to, buffer + clone_from, clone_len);

        //Now copy the rest of the original byte buffer
        memcpy(newBuff + clone_to + clone_len, buffer + clone_to, size - clone_to);

    } else {
        //Clone a large block of the original value

        clone_len = AFLDeleteMutator::choose_block_len(&rand, HAVOC_BLK_XL); //This constant is 32768
        int randomByte = afl_rand_below(&rand, 255);

        int newSize = clone_len + size;
        char* newBuff = newEntry->allocateBuffer(testCaseKey, newSize);

        //Insert clone_len bytes at a location clone_to, the inserted bytes
        //will contain the value in the just determined randomByte
        
        //First copy clone_to bytes from the original buffer
        memcpy((void*)newBuff, (void*)buffer, clone_to);

        //Now copy the new random byte clone_len times
        memset(newBuff + clone_to, randomByte, clone_len);

        //Now copy the rest of the original buffer
        memcpy(newBuff + clone_to + clone_len, buffer + clone_to, size - clone_to);
    }

    return newEntry;
}