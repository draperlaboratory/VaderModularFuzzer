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
#include "ExecutorModule.hpp"
#include <string>

namespace vmf
{
  
/**
 * @brief OutputModule that performs corpus minimization (removes testcases that 
 * don't contribute coverage) and assigns favorability scores to testcases.
 * This module reads the AFL_TRACE_BITS in order to analyze coverage, and analyzes
 * only test cases with the RAN_SUCCESSFULLY tag (e.g. crashing and hanging test cases are
 * not minimized).  The TEST_CASE buffer is re-run with the specified ExecutorModule submodule
 * in order to obtain coverage data, if it is not already present in storage.
 * @image html CoreModuleDataModel_5.png width=800px
 * @image latex CoreModuleDataModel_5.png width=6in
 */
class CorpusMinimization : public OutputModule {
public:
    static Module* build(std::string name);
    virtual void init(ConfigInterface& config);

    CorpusMinimization(std::string name);
    virtual ~CorpusMinimization();

    virtual void registerStorageNeeds(StorageRegistry& registry);
    virtual ScheduleTypeEnum getDesiredScheduleType();
    virtual int getDesiredScheduleRate();

    virtual void run(StorageModule& storage);
    virtual void shutdown(StorageModule& storage);

private:
    int minimizeCorpus(StorageModule& storage);

    bool minimizeOnShutdown;

    int testCaseKey;
    int normalTag;
    int traceBitsKey;

    int minutesBetweenMinimization;
    int formerCorpusSize;

    ExecutorModule* executor;
    char* corpusCoverage;
    unsigned int mapSize;
    std::string outDir;
};
}
