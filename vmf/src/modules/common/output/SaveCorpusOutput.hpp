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

#include "OutputModule.hpp"
#include "RuntimeException.hpp"
#include <string>

namespace vmf
{
/**
 * @brief Output module that saves all new crashed outputs to disk
 *
 */
class SaveCorpusOutput : public OutputModule {
public:
    static Module* build(std::string name);
    virtual void init(ConfigInterface& config);

    SaveCorpusOutput(std::string name);
    virtual ~SaveCorpusOutput();

    virtual void registerStorageNeeds(StorageRegistry& registry);
    virtual void run(StorageModule& storage);

private:
    void outputTestCase(StorageEntry* entry, std::string dir);
    /// The handle for the test case buffer
    int testCaseKey;

    /// The number of tags that this module is monitoring
    int numTags;

    /// The list of tag names that this module is monitoring
    std::vector<std::string> tagNames;

    /// The handles to those tags
    std::vector<int> tagHandles;

    /// The output directories to use for each tag
    std::vector<std::string> tagDirectories;

    /// The output directory for unique test cases
    std::string fdirUnique;
};
}