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

#include "RadamsaMutator.hpp"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <fstream>
#include <iostream>

using namespace vader;
using namespace aflpp;

#include "ModuleFactory.hpp"
REGISTER_MODULE(RadamsaMutator);

/**
 * @brief Builder method to support the ModuleFactory
 * Constructs an instance of this class
 * @return Module* 
 */
Module* RadamsaMutator::build(std::string name)
{
    return new RadamsaMutator(name);
}

/**
 * @brief Initialization method
 * 
 * @param config 
 */
void RadamsaMutator::init(ConfigInterface& config)
{

}

/**
 * @brief Construct a new RadamsaMutator::RadamsaMutator object
 * 
 * @param name name of instance 
 */
RadamsaMutator::RadamsaMutator(std::string name) :
    MutatorModule(name)
{
    srand(time(NULL));
    seed = rand() % 100;
    radamsaBuffer = (char*)malloc(RADAMSA_BUFF_SZ);
    radamsa_init();
}

/**
 * @brief Destroy the RadamsaMutator::RadamsaMutator object
 */
RadamsaMutator::~RadamsaMutator()
{
    free(radamsaBuffer);
}

/**
 * @brief Registers storage needs
 * This class uses only the "TEST_CASE" key
 * 
 * @param registry 
 */
void RadamsaMutator::registerStorageNeeds(StorageRegistry& registry)
{
    testCaseKey = registry.registerKey("TEST_CASE", StorageRegistry::BUFFER, StorageRegistry::READ_WRITE);
}

/**
 * @brief Creates a new test case by mutating the base entry
 * 
 * Creates a new StorageEntry containing a modified test case buffer. 
 * 
 * @param storage reference to storage
 * @param baseEntry the base entry to use for mutation
 * @return StorageEntry* 
 * @throws RuntimeException if baseEntry has an empty test case buffer.
 */
StorageEntry* RadamsaMutator::createTestCase(StorageModule& storage, StorageEntry* baseEntry)
{

  int inputSize = baseEntry->getBufferSize(testCaseKey);
  char* inputBuffer = baseEntry->getBufferPointer(testCaseKey);
  if (inputSize <= 0) 
  {
    throw RuntimeException(
        "RadamsaMutator mutate called with zero sized buffer",
        RuntimeException::USAGE_ERROR);
    }

    uint outputSize = 0;
    outputSize = radamsa((uint8_t*)inputBuffer, inputSize,
                        (uint8_t*)radamsaBuffer, RADAMSA_BUFF_SZ, seed++);

    StorageEntry* newEntry = storage.createNewEntry();
    if(outputSize <=0)
    {
        //Occasionally Radamsa will mutate to an empty buffer
        //printf("RadamsaMutator output of size 0, seed=%d, inputBuffSize=%d, baseEntry=%d\n", seed, inputSize, baseEntry->getID());
        //Just copy what we started with instead
        char* outputBuffer = newEntry->allocateBuffer(testCaseKey, inputSize);
        memcpy(outputBuffer, inputBuffer, inputSize);
    }
    else
    {
        char* outputBuffer = newEntry->allocateBuffer(testCaseKey, outputSize);
        memcpy(outputBuffer, radamsaBuffer, outputSize);
    }

    return newEntry;
}

