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
 * @brief Output module that writes all the variables in metadata to the VMF Logger
 * The rate of this logging is configurable.  Only INT, UINT, and FLOAT type data are supported.
 *
 */
class LoggerMetadataOutput : public OutputModule {
public:
    static Module* build(std::string name);
    virtual void init(ConfigInterface& config);

    virtual void registerStorageNeeds(StorageRegistry& registry);
    virtual void registerMetadataNeeds(StorageRegistry& registry);
    virtual OutputModule::ScheduleTypeEnum getDesiredScheduleType();
    virtual int getDesiredScheduleRate();

    virtual void run(StorageModule& storage);

    LoggerMetadataOutput(std::string name);
    virtual ~LoggerMetadataOutput();

private:
    void loadKeyData(StorageModule& storage);

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