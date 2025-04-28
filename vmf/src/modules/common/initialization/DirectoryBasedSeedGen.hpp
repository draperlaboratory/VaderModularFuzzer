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

#include "Module.hpp"
#include "InitializationModule.hpp"
#include <string>

namespace vmf
{
/**
 * @brief InitializationModule that will create an initial set of test cases from a directory of inputs.
 * These test cases represent an initial set of seeds for use by the fuzzer.  Each input is written to a
 * a TEST_CASE buffer.
 * @image html CoreModuleDataModel_7.png width=800px
 * @image latex CoreModuleDataModel_7.png width=6in
 */
class DirectoryBasedSeedGen: public InitializationModule {
public:
    static Module* build(std::string name);
    virtual void init(ConfigInterface& config);
    virtual void registerStorageNeeds(StorageRegistry& registry);
    virtual void run(StorageModule& storage);

    DirectoryBasedSeedGen(std::string name);
    virtual ~DirectoryBasedSeedGen();
private:
    int testCaseKey;
    std::string fdir;
};
}
