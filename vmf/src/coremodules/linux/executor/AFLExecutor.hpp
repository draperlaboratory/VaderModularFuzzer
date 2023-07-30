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

#include "ExecutorModule.hpp"

namespace vader
{
/**
 * @brief The base class for all AFL++ Executor
 *
 * This is the base class for all executors that use AFL++-style execution patterns
 * 
 */
class AFLExecutor: public ExecutorModule
{
public:

    ///Constant indicating an error occured during execution (used in getReturnStatus())
    static const int AFL_STATUS_ERROR = -1;
    ///Constant indicating nominal execution (used in getReturnStatus())
    static const int AFL_STATUS_OK = 1;
    ///Constant indicating a hang status (used in getReturnStatus())
    static const int AFL_STATUS_HUNG = 2;
    ///Constant indicating a crashed status (used in getReturnStatus())
    static const int AFL_STATUS_CRASHED = 3;

    /**
     * @brief Helper method to cast ExecutorModule* to AFLExecutor*
     * This will throw an exception if the pointer cannot be cast
     * because the underlying type is not a descendant of AFLExecutor.
     * 
     * @param exec the ExecutorModule*
     * @return AFLExecutor* 
     */
    static AFLExecutor* castTo(ExecutorModule* exec)
    {
        AFLExecutor* aflExec = dynamic_cast<AFLExecutor*>(exec);

        if(nullptr == aflExec)
        {
            throw RuntimeException("Executor is not of type AFLExecutor, and was expected to be",
                    RuntimeException::USAGE_ERROR);
        }
        return aflExec;
    }

    virtual void runTestCase(char * buffer, int size) = 0;
    //Note: Implementations may be able to move up a level from AFLForkserverRunner
    //when an additional AFLExecutor is implemented.

    /**
     * @brief Get the Coverage Bits for the last test case that was executed
     * This method returns a pointer to the raw coverage bits.  Use getCoverageSize()
     * to determine how much data can be accessed with this pointer.
     * 
     * @return char* coverage bits
     */
    virtual char* getCoverageBits() = 0;

    /**
     * @brief Returns the coverage bits for the last test case, after first classifying them.
     * This is the same as getCoverageBits, except additional processing to classify the
     * bits is performed first, using the AFL++ classify_counts method.
     * 
     * @return char* a pointer to the coverage bits
     */
    virtual char* getCoverageBitsClassified() = 0;

    /**
     * @brief Returns the size of the coverage bits for the last test case
     * 
     * @return int the size
     */
    virtual int getCoverageSize() = 0;

    /**
     * @brief Indicates whether or not the last test case achieved new coverage
     * This method returns true if new coverage bits were discovered in the
     * last test case run.  Note that the executor is stateful, the coverage
     * will be compared to prior runs.  Uses AFL++ has_new_bits_unclassified.
     * 
     * @return true if there is new coverage
     * @return false otherwise
     */
    virtual bool hasNewCoverageBits() = 0;

    /**
     * @brief Returns the number of bytes covered by the last test case
     * 
     * This method uses AFL++ count_bytes.
     * 
     * @return int the byte count
     */
    virtual int getCoverageByteCount() = 0;

    /**
     * @brief Get the Corpus Coverage Byte Count of the last test case
     * 
     * This method uses ALF++ count_non_255_bytes.
     * 
     * @return int the byte count
     */
    virtual int getCorpusCoverageByteCount() = 0;

    /**
     * @brief Get the execution time of the last test case
     * This time is in microseconds (us).
     * 
     * @return int the time in us
     */
    virtual int getExecutionTime() = 0;

    /**
     * @brief Get the execution status of the last test case
     * This will be one of the status constants:
     * -AFL_STATUS_ERROR
     * -AFL_STATUS_OK
     * -AFL_STATUS_HUNG
     * -AFL_STATUS_CRASHED
     * 
     * @return int the status
     */
    virtual int getReturnStatus() = 0;

    /**
     * @brief Destroy the AFLExecutor object
     */
    virtual ~AFLExecutor() {};
    
protected:
    /**
     * @brief Construct a new AFLExecutor object
     * 
     * @param name the name of the module
     */
    AFLExecutor(std::string name) : ExecutorModule(name) {};
};
}
