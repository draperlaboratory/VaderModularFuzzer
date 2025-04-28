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
 * This module requires ComputeStats (or an equivalent module) to be present, such
 * that a number of required metadata inputs are available.
 * The statistics can be provided to the logger or for distributed fuzzing, or to the server,
 * depending on the configuration options selected.  The default behavior is to
 * write to the logger.
 * @image html CoreModuleDataModel_6.png width=800px
 * @image latex CoreModuleDataModel_6.png width=6in
 */
class StatsOutput : public OutputModule {
public:
    static Module* build(std::string name);
    virtual void init(ConfigInterface& config);

    virtual void registerStorageNeeds(StorageRegistry& registry);
    virtual void registerMetadataNeeds(StorageRegistry& registry);
    virtual OutputModule::ScheduleTypeEnum getDesiredScheduleType();
    virtual int getDesiredScheduleRate();

    virtual void run(StorageModule& storage);

    StatsOutput(std::string name);
    virtual ~StatsOutput();
private:

    void outputStatistics();

    // When true, stats are sent to the server, when false, they are send to the logger instead
    bool writeToServer;
    int outputRate;

    int totalTCCountMetadataKey;
    int totalCrashedCountMetadataKey;
    int totalHungCountMetadataKey;
    int totalBytesCoveredMetadataKey;
    int mapSizeMetadataKey;  
    int secondsSinceLastUniqueMetadataKey;
    int uniqueTCCountMetadataKey;
    int uniqueCrashedCountMetadataKey;
    int uniqueHungCountMetadataKey;
    int latestExecPerSecMetadataKey;
    int averageExecPerSecMetadataKey;


};
}
