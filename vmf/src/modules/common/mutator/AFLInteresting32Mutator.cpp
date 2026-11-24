/* =============================================================================
 * Vader Modular Fuzzer (VMF)
 * Copyright (c) 2021-2026 The Charles Stark Draper Laboratory, Inc.
 * <vmf@draper.com>
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
/* *************
 * Copyright (c) 2026 Vigilant Cyber Systems
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
 * ************/

#include "AFLInteresting32Mutator.hpp"
#include "AFLMutatorCommon.hpp"
#include "RuntimeException.hpp"
#include <random>
#include <algorithm>

using namespace vmf;

#include "ModuleFactory.hpp"
REGISTER_MODULE(AFLInteresting32Mutator);

const int64_t AFLInteresting32Mutator::interesting_32[] = 
{
    INTERESTING_8, 
    INTERESTING_16,
    INTERESTING_32
};

/**
 * @brief Builder method to support the ModuleFactory
 * Constructs an instance of this class
 * @return Module* 
 */
Module* AFLInteresting32Mutator::build(std::string name)
{
    return new AFLInteresting32Mutator(name);
}

/**
 * @brief Initialization method
 * 
 * @param config 
 */
void AFLInteresting32Mutator::init(ConfigInterface& config)
{
    rand = VmfRand::getInstance();
}

/**
 * @brief Construct a new AFLInteresting32Mutator::AFLInteresting32Mutator object
 * 
 * @param name the name of the module
 */
AFLInteresting32Mutator::AFLInteresting32Mutator(std::string name) :
    MutatorModule(name)
{

}

/**
 * @brief Destroy the AFLInteresting32Mutator::AFLInteresting32Mutator object
 * 
 */
AFLInteresting32Mutator::~AFLInteresting32Mutator()
{

}

/**
 * @brief Registers storage needs
 * This class uses only the "TEST_CASE" key
 * 
 * @param registry 
 */
void AFLInteresting32Mutator::registerStorageNeeds(StorageRegistry& registry)
{
    testCaseKey = registry.registerKey("TEST_CASE", StorageRegistry::BUFFER, StorageRegistry::READ_WRITE);
}
 
void AFLInteresting32Mutator::mutateTestCase(StorageModule& storage, StorageEntry* baseEntry, StorageEntry* newEntry, int testCaseKey)
{

    int size = baseEntry->getBufferSize(testCaseKey);
    char* buffer = baseEntry->getBufferPointer(testCaseKey);

    if(size <= 0)
    {
        throw RuntimeException("AFLInteresting32Mutator mutate called with zero sized buffer", RuntimeException::USAGE_ERROR);
    }

    // Copy base entry to new entry
    char* newBuff = newEntry->allocateBuffer(testCaseKey, size);
    memcpy((void*)newBuff, (void*)buffer, size);

    if (size < 4) {
        return;
    }

    // Pick a random byte and replace it with an interesting value
    int item = rand->randBelow(INTERESTING_8_LEN + INTERESTING_16_LEN + INTERESTING_32_LEN);
    *(uint32_t *) (newBuff + rand->randBelow(size - 3)) = AFLInteresting32Mutator::interesting_32[item];

    return;
}