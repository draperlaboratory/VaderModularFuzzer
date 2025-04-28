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
#include "MOPT.hpp"

namespace vmf
{

/**
 * @brief This InputGeneratorModule is an optimized mutator selection approach that is based on the MOpt algorithm.
 * 
 * See https://www.usenix.org/system/files/sec19-lyu.pdf
 * 
 * This module uses the RAN_SUCCESSFULLY tag to select only test cases with a normal execution
 * pattern as the basis of mutation.  It uses MUTATOR_ID to track which MutatorModule submodule
 * was used to create each TEST_CASE, and adjusts how frequently it uses each mutator based on
 * the observed performance of the resulting test cases.
 * @image html CoreModuleDataModel_4.png width=800px
 * @image latex CoreModuleDataModel_4.png width=6in
 */
class MOPTInputGenerator: public InputGeneratorModule
{
public:
    static Module* build(std::string name);
    virtual void init(ConfigInterface& config);

    virtual void registerStorageNeeds(StorageRegistry& registry);
    virtual void addNewTestCases(StorageModule& storage);
    virtual bool examineTestCaseResults(StorageModule& storage);

    MOPTInputGenerator(std::string name);
    virtual ~MOPTInputGenerator();
private:

    StorageEntry* selectBaseEntry(StorageModule& storage);

    MOPT* mopt;
    unsigned int testCasesRan;
    int moptMutatorIdKey;
    int mutatorIdKey;
    int normalTag;
    int testCaseKey;

    std::vector<MutatorModule*> mutators; ///< The list of mutators being managed by this input generator

    std::vector<int> mutatorStats;
    std::vector<int> mutatorStatsTotalTestCases;
};
}
