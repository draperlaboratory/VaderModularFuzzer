/* =============================================================================
 * Vader Modular Fuzzer (VMF)
 * Copyright (c) 2021-2025 The Charles Stark Draper Laboratory, Inc.
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

#include "AFLSpliceMutator.hpp"
#include "RuntimeException.hpp"
#include <algorithm>

using namespace vmf;

#include "ModuleFactory.hpp"
REGISTER_MODULE(AFLSpliceMutator);

/**
 * @brief Builder method to support the ModuleFactory
 * Constructs an instance of this class
 * @return Module* 
 */
Module* AFLSpliceMutator::build(std::string name)
{
    return new AFLSpliceMutator(name);
}

/**
 * @brief Initialization method
 * 
 * @param config 
 */
void AFLSpliceMutator::init(ConfigInterface& config)
{
    rand = VmfRand::getInstance();
}

/**
 * @brief Construct a new AFLSpliceMutator::AFLSpliceMutator object
 * 
 * @param name the name of the module
 */
AFLSpliceMutator::AFLSpliceMutator(std::string name) :
    MutatorModule(name)
{

}

/**
 * @brief Destroy the AFLSpliceMutator::AFLSpliceMutator object
 * 
 */
AFLSpliceMutator::~AFLSpliceMutator()
{

}

/**
 * @brief Registers storage needs
 * 
 * @param registry 
 */
void AFLSpliceMutator::registerStorageNeeds(StorageRegistry& registry)
{
    
    //This module does not register for a test case buffer key, because mutators are told which buffer to write in storage 
    //by the input generator that calls them

    normalTag = registry.registerTag("RAN_SUCCESSFULLY", StorageRegistry::READ_ONLY);
}
 
void AFLSpliceMutator::mutateTestCase(StorageModule& storage, StorageEntry* baseEntry, StorageEntry* newEntry, int testCaseKey)
{

    int size = baseEntry->getBufferSize(testCaseKey);
    char* buffer = baseEntry->getBufferPointer(testCaseKey);
    int baseID = baseEntry->getID();

    if(size <= 0)
    {
        throw RuntimeException("AFLSpliceMutator mutate called with zero sized buffer", RuntimeException::USAGE_ERROR);
    }

    // get a random second test case that will be spliced
    StorageEntry* secondEntry = nullptr;
    int randIndex = 0;

    std::unique_ptr<Iterator> entries = storage.getSavedEntriesByTag(normalTag);
    int maxIndex = entries->getSize();
    // make sure that random case is not the same as the base case
    int secondID = baseID;
    int count=0;
    while((secondID == baseID)&&(count<3))
    {
        randIndex = rand->randBelow(maxIndex);
        secondEntry = entries->setIndexTo(randIndex);
        secondID = secondEntry->getID();
        count++; //We need to prevent an infinite loop in case there are only a few test cases in the queue
    }
    char* secondBuffer = secondEntry->getBufferPointer(testCaseKey);
    int secondSize = secondEntry->getBufferSize(testCaseKey);

    // test cases may not be the same size, bound splice point based on the smaller testcase
    int minSize = std::min(size, secondSize);

    //pick random splice point, from 1 to second to last byte.
    //TODO(VADER-609): Consider limiting splice range to where bytes differ. 
    int splitAt = rand->randBelow(minSize - 1) + 1;

    // secondSize is the size of the new testcase: we copy splitAt bytes from the first,
    // and (secondSize - splitAt) from the second. splitAt + secondSize - splitAt = secondSize.
    char* newBuff = newEntry->allocateBuffer(testCaseKey, secondSize);
    // copy from first test case
    memcpy((void*)newBuff, (void*)buffer, splitAt);
    // copy from second test case
    memcpy((newBuff + splitAt), (secondBuffer + splitAt), (secondSize - splitAt));

}
