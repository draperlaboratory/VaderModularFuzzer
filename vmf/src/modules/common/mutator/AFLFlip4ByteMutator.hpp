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
#pragma once

#include "MutatorModule.hpp"
#include "StorageEntry.hpp"
#include "RuntimeException.hpp"
#include "VmfRand.hpp"

namespace vmf
{
/**
 * @brief This mutator flips a set of 4 bytes in the test case buffer
 * 
 * This module is draws heavily upon the libAFL mutator.c
 * 
 * Uses the specified AFL-style mutation algorithm to mutate the provided
 * input.  mutateTestCase is the main mutation method.
 * 
 * See https://github.com/AFLplusplus/LibAFL-legacy/blob/dev/src/mutator.c
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
 */
class AFLFlip4ByteMutator: public MutatorModule
{
public:

    static Module* build(std::string name);
    virtual void init(ConfigInterface& config);

    AFLFlip4ByteMutator(std::string name);
    virtual ~AFLFlip4ByteMutator();
    virtual void registerStorageNeeds(StorageRegistry& registry);
    virtual void mutateTestCase(StorageModule& storage, StorageEntry* baseEntry, StorageEntry* newEntry, int testCaseKey);
    
private:
    VmfRand* rand;

};
}
