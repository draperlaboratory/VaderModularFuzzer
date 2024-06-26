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
#include "DirectoryBasedSeedGen.hpp"
#include "Logging.hpp"
#include "VmfUtil.hpp"

#include <sys/types.h>
#include <string.h>

using namespace vmf;

#include "ModuleFactory.hpp"
REGISTER_MODULE(DirectoryBasedSeedGen);

/**
 * @brief Builder method to support the ModuleFactory
 * Constructs an instance of this class
 * @return Module* 
 */
Module* DirectoryBasedSeedGen::build(std::string name)
{
    return new DirectoryBasedSeedGen(name);
}

/**
 * @brief Initialization method
 * Reads in all configuration options for this class
 *
 * @param config
 */
void DirectoryBasedSeedGen::init(ConfigInterface& config)
{
    std::string inputDir;

    try
    {
        inputDir = config.getStringParam(getModuleName(), "inputDir");
    }
    catch(RuntimeException e)
    {
        LOG_ERROR << "List of module parameters found: " << config.getAllParams(getModuleName());
        throw e;
    }

    if(inputDir.back() != '/')
    {
        fdir = inputDir + '/';
    }
    else
    {
        fdir = inputDir;
    }
}

/**
 * @brief Construct a new Directory Based Seed Gen module
 * 
 * @param name the name of the module
 */
DirectoryBasedSeedGen::DirectoryBasedSeedGen(std::string name) :
    InitializationModule(name)
{

}

DirectoryBasedSeedGen::~DirectoryBasedSeedGen()
{

}

void DirectoryBasedSeedGen::registerStorageNeeds(StorageRegistry& registry)
{
    testCaseKey = registry.registerKey("TEST_CASE", StorageRegistry::BUFFER, StorageRegistry::WRITE_ONLY);
}

void DirectoryBasedSeedGen::run(StorageModule& storage)
{
    int numCreated = VmfUtil::createNewTestCasesFromDir(storage, testCaseKey, fdir);
    if(numCreated<=0){
        LOG_WARNING << "No test cases were found in the input directory";
    }
}
