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
#include "MyMutator.hpp"
#include "Logging.hpp"

using namespace vmf;

/*
  This will register the mutator module with the VMF module factory, making
  it available for use via VMF configuration files.
 */
#include "ModuleFactory.hpp"
REGISTER_MODULE(MyMutator);

/**
 * @brief Builder method to support the ModuleFactory
 * Constructs an instance of this class
 * @return Module* 
 */
Module* MyMutator::build(std::string name)
{
    return new MyMutator(name);
}

/**
 * @brief Initialization method
 * Reads in all configuration options for this class, including:
 *    Nothing at the moment
 * 
 * @param config 
 */
void MyMutator::init(ConfigInterface& config)
{
}

/**
 * @brief Construct a new MyMutator::MyMutator object
 * 
 * @param name name of instance 
 */
MyMutator::MyMutator(std::string name) :
    MutatorModule(name)
{
}

/**
 * @brief Destroy the MyMutator::MyMutator object
 */
MyMutator::~MyMutator()
{
}

/**
 * @brief Registers storage needs
 * 
 * @param registry 
 */
void MyMutator::registerStorageNeeds(StorageRegistry& registry)
{
    //This module has no direct needs, because mutators are told where to write in storage by the input generator that calls them
}

/**
 * @brief Creates a new test case by mutating the base entry
 * 
 * Creates a new StorageEntry containing a modified test case buffer. 
 * 
 * @param storage reference to storage
 * @param baseEntry the base entry to use for mutation
 * @param newEntry the test case to write to
 * @param testCaseKey the field to write to in the new entry
 * @throws RuntimeException if baseEntry has an empty test case buffer.
 */
void MyMutator::mutateTestCase(StorageModule& storage, StorageEntry* baseEntry, StorageEntry* newEntry, int testCaseKey)
{
    int inputSize = baseEntry->getBufferSize(testCaseKey);

    if (inputSize <= 0) 
    {
	throw RuntimeException(
	    "MyMutator mutate called with zero sized buffer",
	    RuntimeException::USAGE_ERROR);
    }

    // This doesn't really do anything useful - this is just an
    // integration demonstration.
    LOG_INFO << "Not really mutating here, just pretending";
    char* outputBuffer = newEntry->allocateBuffer(testCaseKey, 23);
    strcpy(outputBuffer, "foobar");
    
}
