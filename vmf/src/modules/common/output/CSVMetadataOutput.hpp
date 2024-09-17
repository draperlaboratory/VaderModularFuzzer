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
 * @brief Output module that writes all the variables in metadata to a CSV file
 * The rate of this logging is configurable.  Only INT, UINT, and FLOAT type data are supported.
 *
 */
class CSVMetadataOutput : public OutputModule {
public:
    static Module* build(std::string name);
    virtual void init(ConfigInterface& config);

    virtual void registerStorageNeeds(StorageRegistry& registry);
    virtual void registerMetadataNeeds(StorageRegistry& registry);
    virtual OutputModule::ScheduleTypeEnum getDesiredScheduleType();
    virtual int getDesiredScheduleRate();

    virtual void run(StorageModule& storage);

    CSVMetadataOutput(std::string name);
    virtual ~CSVMetadataOutput();

private:
    void loadKeyDataAndWriteHeader(StorageModule& storage);
    std::string outputFile;

    int outputRate;
    bool keysLoaded;
    std::vector<int> intKeys;
    std::vector<int> uintKeys;
    std::vector<int> floatKeys;

    std::vector<std::string> intKeyNames;
    std::vector<std::string> uintKeyNames;
    std::vector<std::string> floatKeyNames;
};
}