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
 * case to generato inputs from next.
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
    std::vector<MutatorModule*> mutators; ///< The list of mutators being managed by this input generator
};
}
