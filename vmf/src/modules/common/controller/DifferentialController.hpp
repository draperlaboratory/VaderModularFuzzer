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
 *
 * ===========================================================================*/
#pragma once

// include common modules
#include "ControllerModulePattern.hpp"


namespace vmf
{
/**
 * @brief Controller that is capable of managing multiple storage, execution, and feedback modules
 * for comparing two differential binaries. Campaign rounds are similar to IterativeController.
 * This controller supports one InputGenerator and Feedback modules, two Executors,
 * and any number of Initialization and Output modules.
 */
class DifferentialController : public ControllerModulePattern {
public:

    static Module* build(std::string name);
    virtual void init(ConfigInterface& config);
    virtual void executeTestCases(bool firstPass, StorageModule& storage);

    //This controller has no additional storage needs
    virtual void registerStorageNeeds(StorageRegistry& registry);
    //virtual void registerMetadataNeeds(StorageRegistry& registry);

    virtual bool run(StorageModule& storage, bool isFirstPass);

    DifferentialController(std::string name);
    virtual ~DifferentialController();

private:
    std::vector<int> executorIdTags;
    int batchNumIdKey;
};
}