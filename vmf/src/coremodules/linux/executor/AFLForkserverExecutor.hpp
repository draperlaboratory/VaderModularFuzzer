/* =============================================================================
 * Vader Modular Fuzzer (VMF)
 * Copyright (c) 2021-2023 The Charles Stark Draper Laboratory, Inc.
 * <vader@draper.com>
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

#include "AFLExecutor.hpp"

#include <fcntl.h>
#include <map>

//These have to be included before the aflpp include
//Otherwise these functions end up in the aflpp namespace
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <stdbool.h>

namespace aflpp {
extern "C" {
    #include "AFLplusplus/afl-fuzz.h"
    #include "AFLplusplus/forkserver.h"
    #include "AFLplusplus/sharedmem.h"
    #include "AFLplusplus/common.h"
}
}

namespace vader
{
/**
 * @brief Module that uses AFL++ forkserver for running test cases
 */
class AFLForkserverExecutor : AFLExecutor 
{
public:
    static Module* build(std::string name);
    virtual void init(ConfigInterface& config);
    virtual void runTestCase(char* buffer, int size);
    virtual void runCalibrationCase(char* buffer, int size);
    virtual void completeCalibration();

    virtual char* getCoverageBits();
    virtual char* getCoverageBitsClassified();  
    virtual int getCoverageSize();
    virtual bool hasNewCoverageBits();
    virtual int getCoverageByteCount();
    virtual int getCorpusCoverageByteCount();
    virtual int getExecutionTime();
    virtual int getReturnStatus(); 

    AFLForkserverExecutor(std::string name);
    virtual ~AFLForkserverExecutor();

private:

    aflpp::afl_state_t afl_state;
    aflpp::u8* old_bits;
    volatile aflpp::u8 fsrv_signal_stop;
    aflpp::sharedmem_t shm;
    char tmpOutFile[256];
    int returnStatus;
    int timeTaken;
    aflpp::u32 map_size; //bytes

    bool useManualTimeout;
    int manualTimeoutMs;
    int numCalibrationTestCases;
    int maxTime;
    int sumTime;
};
}
