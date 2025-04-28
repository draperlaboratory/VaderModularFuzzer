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
#include <vector>

namespace vmf
{

/**
 * @brief Helper class to aid in scheduling OutputModules
 * This class can be used by a Controller module to handle scheduling of
 * individual output modules at their desired rate.
 */
class OutputScheduler{
public:
    OutputScheduler();
    ~OutputScheduler();

    void setOutputModules(std::vector<OutputModule*> outputs);
    void runOutputModules(int newTestCaseCount, StorageModule& storage);

private:
    struct OutputModuleData
    {
        time_t lastRanTime; //the time the module last ran (for time based scheduling)
        int testCaseCounter; //test cases to execute before running again (for test case based scheduling)
        int rate; //the number of seconds or test cases between runs
        OutputModule::ScheduleTypeEnum type;
        OutputModule* theModule;
    };

    void loadModuleScheduleRates();

    bool modulesSet;
    bool initialized;
    std::vector<OutputModuleData> moduleData;


};

}