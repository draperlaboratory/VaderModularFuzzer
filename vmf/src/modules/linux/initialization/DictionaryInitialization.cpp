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
#include "DictionaryInitialization.hpp"
#include "Logging.hpp"
#include "VmfUtil.hpp"
#include "RuntimeException.hpp"

#include <string>
#include <iostream>
#include <sstream>

#include <cstdarg>
#include <filesystem>
#include <fstream>
#include <memory>
#include <cstdio>

using namespace vmf;

#include "ModuleFactory.hpp"
REGISTER_MODULE(DictionaryInitialization);

/**
 * @brief Constructor
 * 
 * @param name the name of the module.
 */
DictionaryInitialization::DictionaryInitialization(std::string name) :
    InitializationModule(name)
{}


DictionaryInitialization::~DictionaryInitialization()
{}

/**
 * @brief builder method to support the `ModuleFactory`
 * Constructs an instance of the class, and returns a pointer to the caller.
 * 
 * @param name the name of the module.
 */
Module* DictionaryInitialization::build(std::string name)
{
    return new DictionaryInitialization(name);
}

/**
 * @brief initialization method
 * Retrieve the path to the 'sut' binary.
 * 
 * @param config the ConfigInterface
 * @throws RuntimeException if directory of output dictionary path is non-existant
 */
void DictionaryInitialization::init(ConfigInterface& config)
{
    LOG_INFO << "Initializing DictionaryInitialization";
    sut_path = config.getStringVectorParam(getModuleName(),"sutArgv")[0];
    output_base = config.getOutputDir();

    // check that directories exist
    if (std::filesystem::exists(output_base)) {
        dictionary_path_hardcode = output_base / std::filesystem::path("strings.dict");
    } else {
        LOG_ERROR << "Failed to find output directory: " << output_base;
        throw RuntimeException("Non-existent output directory", RuntimeException::OTHER);
    }

}

/**
 * @brief establish the storage needs of the Initialization Module
 * 
 * @param registry the StorageRegistry with which storage needs are registered.
 */
void DictionaryInitialization::registerStorageNeeds(StorageRegistry& registry)
{
}

/**
 * @brief perform the initialization step
 * Execute the `strings` command on the SUT binary and create a set containing
 * the unique strings in the binary.  All strings dumped to configured path.
 * 
 * @param storage the StorageModule with which the test cases are registered.
 * @throws RuntimeException if executing `strings` fails
 * @throws RuntimeException if it fails to open the output file for writing the 
 *                          strings to.
 */
void DictionaryInitialization::run(StorageModule& storage)
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

    
    // Define path to output file of strings discovered in binary
    LOG_INFO << "Strings in executable written to: " << dictionary_path_hardcode;

    // open file to dump strings to
    std::ofstream outFile;
    outFile.open(dictionary_path_hardcode);
    char buffer[256];
    if (outFile.is_open()){
        while (!feof(pipe.get())) { //while not end of output
            if (fgets(buffer, 256, pipe.get()) != NULL) //read next line
            {
                //create new test case
                std::string response(buffer);
                // remove newline at end of output
                response.erase(std::remove(response.begin(), response.end(), '\n'), response.cend());
                
                outFile << "token=\"" << response << "\"" << std::endl;
            }
        }
        outFile.close();
    } else {
        throw RuntimeException("Failed to open output file", RuntimeException::SERVER_ERROR);
    }
}
