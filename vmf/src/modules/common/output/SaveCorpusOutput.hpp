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

#include "OutputModule.hpp"
#include "RuntimeException.hpp"
#include <string>

namespace vmf
{
/**
 * @brief OutputModule that saves all interesting outputs to disk
 * By default, this module reads the CRASHED and HUNG tags in order to
 * save a copy of each test case that is tagged with these tags to disk.
 * But this module may be configured to save other tags to disk as well.
 * It additionally writes to disk all test cases that are saved to long term to 
 * storage (as these are unique, interesting test cases).
 * @image html CoreModuleDataModel_6.png width=800px
 * @image latex CoreModuleDataModel_6.png width=6in
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

    /// The handle for the mutator ID
    int mutatorIdKey;

    /// The number of tags that this module is monitoring
    int numTags;

    /// The list of tag names that this module is monitoring
    std::vector<std::string> tagNames;

    /// Config option to record mutators used for each test case
    bool recordTestMetadata;

    /// The handles to those tags
    std::vector<int> tagHandles;

    /// The output directories to use for each tag
    std::vector<std::string> tagDirectories;

    /// The output directory for unique test cases
    std::string fdirUnique;

    /// Saved reference to config provided during init
    ConfigInterface* config;
};
}
