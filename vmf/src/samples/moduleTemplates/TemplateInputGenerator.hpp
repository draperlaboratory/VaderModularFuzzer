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

using namespace vmf;

class TemplateInputGenerator : public InputGeneratorModule
{
public:
    static Module* build(std::string name);
    virtual void init(ConfigInterface& config);
    
    TemplateInputGenerator(std::string name);
    virtual ~TemplateInputGenerator();
    virtual void registerStorageNeeds(StorageRegistry& registry);
    //virtual void registerMetadataNeeds(StorageRegistry& registry);

    virtual void addNewTestCases(StorageModule& storage);
    //virtual bool examineTestCaseResults(StorageModule& storage);
  
private:
    int testCaseKey; ///< Handle for the buffer that contains the test case

    std::vector<MutatorModule*> mutators; ///< The list of mutators being managed by this input generator
    int normalTag; ///< Handle for test cases that ran normally (without crashing or hanging)
};