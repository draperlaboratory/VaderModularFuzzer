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
#include "TemplateInitialization.hpp"
#include "Logging.hpp"

using namespace vmf;

/*
  This will register the mutator module with the VMF module factory, making
  it available for use via VMF configuration files.
 */
#include "ModuleFactory.hpp"
REGISTER_MODULE(TemplateInitialization);

/**
 * @brief Builder method to support the ModuleFactory
 * Constructs an instance of this class
 * @return Module* 
 */
Module* TemplateInitialization::build(std::string name)
{
    return new TemplateInitialization(name);
}

/**
 * @brief Initialization method
 * Reads in all configuration options for this class
 * 
 * @param config 
 */
void TemplateInitialization::init(ConfigInterface& config)
{
    //Call upon the config option to read any config parameters, such as
    //config.getIntParam(getModuleName(), "parameterName");
}

/**
 * @brief Construct a new TemplateInitialization::TemplateInitialization object
 * 
 * @param name name of instance 
 */
TemplateInitialization::TemplateInitialization(std::string name) :
    InitializationModule(name)
{
}

/**
 * @brief Destroy the TemplateInitialization::TemplateInitialization object
 */
TemplateInitialization::~TemplateInitialization()
{
}

/**
 * @brief Registers storage needs
 * 
 * @param registry 
 */
void TemplateInitialization::registerStorageNeeds(StorageRegistry& registry)
{
    testCaseKey = registry.registerKey("TEST_CASE", StorageRegistry::BUFFER, StorageRegistry::WRITE_ONLY);
}

/**
 * @brief Perform any initialization
 * This method is the meat of the initialization module.  It should
 * perform any designed initialization steps (e.g. seed generation).
 * This is only called once, upfront, before other modules are called
 * upon to run.
 * 
 * @param storage 
 */
void TemplateInitialization::run(StorageModule& storage)
{
    //Typical initialization modules create seed test cases
    //Here is an example that creates a test case with the hardcoded single byte value 'A'
    StorageEntry* newEntry = storage.createNewEntry();
    char* buff = newEntry->allocateBuffer(testCaseKey, 1);
    buff[0] = 'A';

    LOG_INFO << "Created one seed test case with UID=" << newEntry->getID();
}

/* ------------The methods below are optional for InitializationModules -------------- */

/**
 * @brief Modules using global metadata must also register fields that they intend to read or write
 *
 * Not all modules use metadata (which is summary data collected across the entries stored in storage),
 * hence this is an optional method.
 *
 * @param registry
 */
/*void TemplateInitialization::registerMetadataNeeds(StorageRegistry& registry)
{

}*/