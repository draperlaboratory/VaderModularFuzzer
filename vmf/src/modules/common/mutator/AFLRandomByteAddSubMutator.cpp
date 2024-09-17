/* =============================================================================
 * Vader Modular Fuzzer (VMF)
 * Copyright (c) 2021-2024 The Charles Stark Draper Laboratory, Inc.
 * <vmf@draper.com>
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

#include "AFLRandomByteAddSubMutator.hpp"
#include "RuntimeException.hpp"
#include <algorithm>

using namespace vmf;

#include "ModuleFactory.hpp"
REGISTER_MODULE(AFLRandomByteAddSubMutator);

/**
 * @brief Builder method to support the ModuleFactory
 * Constructs an instance of this class
 * @return Module* 
 */
Module* AFLRandomByteAddSubMutator::build(std::string name)
{
    return new AFLRandomByteAddSubMutator(name);
}

/**
 * @brief Initialization method
 * 
 * @param config 
 */
void AFLRandomByteAddSubMutator::init(ConfigInterface& config)
{
    rand = VmfRand::getInstance();
}

/**
 * @brief Construct a new AFLRandomByteAddSubMutator::AFLRandomByteAddSubMutator object
 * 
 * @param name the name of the module
 */
AFLRandomByteAddSubMutator::AFLRandomByteAddSubMutator(std::string name) :
    MutatorModule(name)
{
    rand = nullptr;
}

/**
 * @brief Destroy the AFLRandomByteAddSubMutator::AFLRandomByteAddSubMutator object
 * 
 */
AFLRandomByteAddSubMutator::~AFLRandomByteAddSubMutator()
{

}

/**
 * @brief Registers storage needs
 * 
 * @param registry 
 */
void AFLRandomByteAddSubMutator::registerStorageNeeds(StorageRegistry& registry)
{
    //This module does not register for a test case buffer key, because mutators are told which buffer to write in storage 
    //by the input generator that calls them
}
 
void AFLRandomByteAddSubMutator::mutateTestCase(StorageModule& storage, StorageEntry* baseEntry, StorageEntry* newEntry, int testCaseKey)
{
    if (rand == nullptr)
    {
	throw RuntimeException("VmfRand was null, mutator was not initialized before use.");
    }

    int size = baseEntry->getBufferSize(testCaseKey);
    char* buffer = baseEntry->getBufferPointer(testCaseKey);

    if(size <= 0)
    {
        throw RuntimeException("AFLRandomByteAddSubMutator mutate called with zero sized buffer", RuntimeException::USAGE_ERROR);
    }

    int byte = rand->randBelow(size);
    char* newBuff = newEntry->allocateBuffer(testCaseKey, size);
    memcpy((void*)newBuff, (void*)buffer, size);
    newBuff[byte] -= 1 + (uint8_t)rand->randBelow(ARITH_MAX);
    newBuff[byte] += 1 + (uint8_t)rand->randBelow(ARITH_MAX);
}
