/* =============================================================================
 * Vader Modular Fuzzer (VMF)
 * Copyright (c) 2023 Vigilant Cyber Systems
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
#include "GramatronBasedSeedGen.hpp"

#include "ModuleFactory.hpp"
using namespace vmf;

REGISTER_MODULE(GramatronBasedSeedGen);

/**
 * @brief Builder method to support the ModuleFactory
 * Constructs an instance of this class
 * @return Module* 
 */
Module* GramatronBasedSeedGen::build(std::string name)
{
    return new GramatronBasedSeedGen(name);
}

/**
 * @brief Initialization method
 * Reads in all configuration options for this class
 * 
 * @param config 
 */
void GramatronBasedSeedGen::init(ConfigInterface& config)
{
    std::string PDAPath = config.getStringParam(getModuleName(), "PDAPath");
    numTestCases = config.getIntParam(getModuleName(), "numTestCases");

    pda = PDA::CreateInstance(PDAPath);
}

/**
 * @brief Construct a new Gramatron Based Seed Gen module
 * 
 * @param name the name of the module
 */
GramatronBasedSeedGen::GramatronBasedSeedGen(std::string name) :
    InitializationModule(name)
{

}

GramatronBasedSeedGen::~GramatronBasedSeedGen()
{

}

void GramatronBasedSeedGen::registerStorageNeeds(StorageRegistry& registry)
{
    testCaseKey = registry.registerKey("TEST_CASE", StorageRegistry::BUFFER, StorageRegistry::WRITE_ONLY);
    autRepKey = registry.registerKey("TEST_CASE_AUT", StorageRegistry::BUFFER, StorageRegistry::WRITE_ONLY);
}

void GramatronBasedSeedGen::run(StorageModule& storage)
{
    createNewTestCasesFromPDA(storage, testCaseKey, autRepKey, numTestCases);
}
