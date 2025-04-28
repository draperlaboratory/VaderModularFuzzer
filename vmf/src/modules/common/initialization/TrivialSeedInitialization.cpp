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
#include "TrivialSeedInitialization.hpp"
#include "Logging.hpp"
#include "VmfUtil.hpp"

#include <sys/types.h>
#include <string.h>

using namespace vmf;

#include "ModuleFactory.hpp"
REGISTER_MODULE(TrivialSeedInitialization);

/**
 * @brief Builder method to support the ModuleFactory
 * Constructs an instance of this class
 * @return Module* 
 */
Module* TrivialSeedInitialization::build(std::string name)
{
    return new TrivialSeedInitialization(name);
}

/**
 * @brief Initialization method
 * Reads in all configuration options for this class
 *
 * @param config
 */
void TrivialSeedInitialization::init(ConfigInterface& config)
{
    // nothing to initialize
}

/**
 * @brief Construct a new Directory Based Seed Gen module
 * 
 * @param name the name of the module
 */
TrivialSeedInitialization::TrivialSeedInitialization(std::string name) :
    InitializationModule(name)
{

}

TrivialSeedInitialization::~TrivialSeedInitialization()
{

}

void TrivialSeedInitialization::registerStorageNeeds(StorageRegistry& registry)
{
    testCaseKey = registry.registerKey("TEST_CASE", StorageRegistry::BUFFER, StorageRegistry::READ_ONLY);
}

void TrivialSeedInitialization::run(StorageModule& storage)
{
    // store trivial canned seed
    int seed_len = 5;
    char seed[] = {'h', 'e', 'l', 'l', 'o'};
    StorageEntry* newEntry = storage.createNewEntry();
    newEntry->allocateAndCopyBuffer(testCaseKey, seed_len, seed);
}
