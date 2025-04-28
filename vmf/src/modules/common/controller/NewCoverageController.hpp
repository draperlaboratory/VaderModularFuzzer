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

#include "ControllerModulePattern.hpp"

namespace vmf
{
/**
 * @brief Controller that toggles between two InputGenerator modules
 * The NewCoverageController is similar to the IterativeController, except
 * that it supports two InputGenerator modules.  This controller will temporarily
 * toggle to an alternative input generator every time there is are new, interesting
 * test cases saved in storage (typically this occurs due to new coverage, though 
 * the exact decision is made in the feedback module).  The examineTestCaseResults()
 * method is called on both input generators during each pass through the fuzzing loop, 
 * but the addNewTestCases() method is called on only the active input generator.
 * 
 */
class NewCoverageController : public ControllerModulePattern {
public:

    static Module* build(std::string name);
    virtual void init(ConfigInterface& config);
    //This controller has no additional storage needs
    //virtual void registerStorageNeeds(StorageRegistry& registry);
    //virtual void registerMetadataNeeds(StorageRegistry& registry);
    virtual bool run(StorageModule& storage, bool isFirstPass);

    NewCoverageController(std::string name);
    virtual ~NewCoverageController();

protected:

    virtual void executeTestCases(bool firstPass, StorageModule& storage);
    void selectNextInputGenerator();

    /// The main input generator (which will run until new coverage is encountered)
    InputGeneratorModule* primaryInputGen;
    /// The secondary input generator (which will run when the first input generator finds new coverage)
    InputGeneratorModule* newCoverageInputGen;
    /// Currently active InputGenerator:
    InputGeneratorModule* currentInputGen;
    /// State tracking for NewCoverageController, was there new coverage
    bool foundNewCoverageThisCycle = false;
    /// State tracking for NewCoverageController, does the input generator want to run again
    bool inputGenRunAgain = false;

};
}
