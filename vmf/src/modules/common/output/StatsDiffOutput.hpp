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

namespace vmf
{
/**
 * @brief OutputModule that logs high level execution statistics for the operator.
 * This module requires ComputeDiffStats (or an equivalent module) to be present, such
 * that a number of required differential metadata inputs are available.
 * Statistics will be provided to the logger.
 * @image html CoreModuleDataModel_6.png width=800px
 * @image latex CoreModuleDataModel_6.png width=6in
 */
class StatsDiffOutput : public OutputModule {
public:
    static Module* build(std::string name);
    virtual void init(ConfigInterface& config);

    virtual void registerStorageNeeds(StorageRegistry& registry);
    virtual void registerMetadataNeeds(StorageRegistry& registry);
    virtual OutputModule::ScheduleTypeEnum getDesiredScheduleType();
    virtual int getDesiredScheduleRate();

    virtual void run(StorageModule& storage);

    StatsDiffOutput(std::string name);
    virtual ~StatsDiffOutput();
private:
    template <typename T, typename V>
    void odl(int l_width, std::vector<T> dataCenter, std::vector<V> dataRight, std::string postfix);
    template<typename T, typename V>
    void ogl(int l_width, int r_width, T uqData, V allData, std::string statName);

    int outputRate;
    unsigned int format_rspace;
    std::vector<std::string> executorNames;

    // single metadata keys
    int grandUQTotalMetadataKey;
    int grandUQCrashedMetadataKey;
    int grandUQHungMetadataKey;
    int grandUQDiffMetadataKey;

    int grandTotalMetadataKey;
    int grandCrashedMetadataKey;
    int grandHungMetadataKey;
    int grandDiffMetadataKey;

    // per-executor metadata keys
    std::vector<int> executorAllTCMetadataKeys;
    std::vector<int> executorAllCrashMetadataKeys;
    std::vector<int> executorAllHungMetadataKeys;
    std::vector<int> executorAllDiffMetadataKeys;

    std::vector<int> executorUQTCMetadataKeys;
    std::vector<int> executorUQCrashMetadataKeys;
    std::vector<int> executorUQHungMetadataKeys;
    std::vector<int> executorUQDiffMetadataKeys;

    std::vector<int> executorAverageEPSMetadataKeys;
    std::vector<int> executorLatestEPSMetadataKeys;
    std::vector<int> executorStaleDurationMetadataKeys;
};
}
