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
#include "TemplateMutator.hpp"
#include "Logging.hpp"

using namespace vmf;

/*
  This will register the mutator module with the VMF module factory, making
  it available for use via VMF configuration files.
 */
#include "ModuleFactory.hpp"
REGISTER_MODULE(TemplateMutator);

/**
 * @brief Builder method to support the ModuleFactory
 * Constructs an instance of this class
 * @return Module* 
 */
Module* TemplateMutator::build(std::string name)
{
    return new TemplateMutator(name);
}

/**
 * @brief Initialization method
 * Reads in all configuration options for this class
 * 
 * @param config 
 */
void TemplateMutator::init(ConfigInterface& config)
{
    //Call upon the config option to read any config parameters, such as
    //config.getIntParam(getModuleName(), "parameterName");
}

/**
 * @brief Construct a new TemplateMutator::TemplateMutator object
 * 
 * @param name name of instance 
 */
TemplateMutator::TemplateMutator(std::string name) :
    MutatorModule(name)
{
}

/**
 * @brief Destroy the TemplateMutator::TemplateMutator object
 */
TemplateMutator::~TemplateMutator()
{
}

/**
 * @brief Registers storage needs
 * 
 * @param registry 
 */
void TemplateMutator::registerStorageNeeds(StorageRegistry& registry)
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
void TemplateMutator::mutateTestCase(StorageModule& storage, StorageEntry* baseEntry, StorageEntry* newEntry, int testCaseKey)
{
    int inputSize = baseEntry->getBufferSize(testCaseKey);

    if (inputSize <= 0) 
    {
	    throw RuntimeException("TemplateMutator mutate called with zero sized buffer",
	          RuntimeException::USAGE_ERROR);
    }

    //Allocate the new test case buffer (here we go ahead and also copy what was in the baseEntry)
    char* outputBuffer = newEntry->allocateAndCopyBuffer(testCaseKey,baseEntry);

    //Then actually mutate the test case -- here we just add one to the first byte as an example
    outputBuffer[0] += 1;

    //See also: VmfRand for randomization functions to use in mutation.
}

/* ------------The methods below are optional for MutatorModules -------------- */

/**
 * @brief Modules using global metadata must also register fields that they intend to read or write
 *
 * Not all modules use metadata (which is summary data collected across the entries stored in storage),
 * hence this is an optional method.
 *
 * @param registry
 */
/*void TemplateMutator::registerMetadataNeeds(StorageRegistry& registry)
{

}*/
