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
#include "StringsInitialization.hpp"
#include "Logging.hpp"
#include "VmfUtil.hpp"

#include <string>
#include <iostream>
#include <sstream>

#include <cstdarg>
#include <fstream>
#include <memory>
#include <cstdio>

using namespace vmf;

#include "ModuleFactory.hpp"
REGISTER_MODULE(StringsInitialization);

/**
 * @brief Constructor
 * initialize the set of strings in the SUT
 * 
 * @param name the name of the module.
 */
StringsInitialization::StringsInitialization(std::string name) :
    InitializationModule(name)
{}


StringsInitialization::~StringsInitialization()
{}

/**
 * @brief builder method to support the `ModuleFactory`
 * Constructs an instance of the class, and returns a pointer to the caller.
 * 
 * @param name the name of the module.
 */
Module* StringsInitialization::build(std::string name)
{
    return new StringsInitialization(name);
}

/**
 * @brief initialization method
 * Retrieve the path to the 'sut' binary.
 * 
 * @param config the ConfigInterface
 */
void StringsInitialization::init(ConfigInterface& config)
{
   sut_path = config.getStringVectorParam(getModuleName(),"sutArgv")[0];
}

/**
 * @brief establish the storage needs of the Initialization Module
 * 
 * @param registry the StorageRegistry with which storage needs are registered.
 */
void StringsInitialization::registerStorageNeeds(StorageRegistry& registry)
{
    testCaseKey = registry.registerKey(
        "TEST_CASE",
        StorageRegistry::BUFFER,
        StorageRegistry::WRITE_ONLY
    );
}

/**
 * @brief perform the initialization step
 * Execute the `strings` command on the SUT binary and create a set containing
 * the unique strings in the binary. 
 *
 * Take those strings and create new test cases for each string. 
 * @param storage the StorageModule with which the test cases are registered.
 */
void StringsInitialization::run(StorageModule& storage)
{
    // Execute `strings` on the sut and get its output.
    std::string cmd = "strings " + sut_path;
    
    //Open pipe
    std::shared_ptr<FILE> pipe(popen(cmd.c_str(), "r"), pclose);
    if (!pipe)
        throw RuntimeException(
            "Executing 'strings' command failed.",
            RuntimeException::OTHER
        );

    char buffer[256];
    while (!feof(pipe.get())) { //while not end of output
        if (fgets(buffer, 256, pipe.get()) != NULL) //read next line
        {
            //create new test case
            std::string response(buffer);
            StorageEntry* entry = storage.createNewEntry();
            int size = response.length() + 1;
            char* buff = entry->allocateBuffer(testCaseKey, size);
            response.copy(buff,size);
        }
    }
}

