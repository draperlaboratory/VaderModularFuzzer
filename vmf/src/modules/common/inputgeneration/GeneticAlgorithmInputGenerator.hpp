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

#include "InputGeneratorModule.hpp"
#include "MutatorModule.hpp"
#include <map>

namespace vmf
{
/**
 * @brief Input generator based on Genetic Algorithm based technique
 *
 * This input generator does a weighted random selection of which test
 * case to generate inputs from next, using the RAN_SUCCESSFULLY tag to select only 
 * test cases with a normal execution pattern as the basis of mutation (unless the 
 * enableMutationOfCrashes config option is set, in which case it will select from all test cases).  
 * It uses its MutatorModule submodules to perform the actual mutations, which will output new
 * TEST_CASE buffers.
 * @image html CoreModuleDataModel_4.png width=800px
 * @image latex CoreModuleDataModel_4.png width=6in
 */
class GeneticAlgorithmInputGenerator: public InputGeneratorModule
{
public:
    static Module* build(std::string name);
    virtual void init(ConfigInterface& config);

    virtual void registerStorageNeeds(StorageRegistry& registry);
    virtual void addNewTestCases(StorageModule& storage);

    GeneticAlgorithmInputGenerator(std::string name);
    virtual ~GeneticAlgorithmInputGenerator();
private:

    StorageEntry* selectBaseEntry(StorageModule& storage);

    bool mutateCrashingCases; ///< Flag to control whether or not crashing test cases are mutated
    int normalTag; ///< Handle for test cases that ran normally (without crashing or hanging)
    int testCaseKey; ///< Handle for the buffer that contains the test case
    int mutatorIdKey;
    std::vector<MutatorModule*> mutators; ///< The list of mutators being managed by this input generator
};
}
