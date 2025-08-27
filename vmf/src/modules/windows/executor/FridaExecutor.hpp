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
#include <windows.h>

#include <stdbool.h>
#include <limits.h>

#include "AFLCoverageUtil.hpp"
#include "ExecutorModule.hpp"
#include "SimpleStorage.hpp"

namespace vmf
{

/**
 * @brief Module that uses AFL++ forkserver for running test cases
 */
class FridaExecutor : public ExecutorModule
{
public:
    /* Virtual functions required by class Module */
    virtual void init(ConfigInterface& config);
    /* Virtual functions required by class ExecutorModule */
    virtual void runTestCase(StorageModule& storage, StorageEntry* entry);
    virtual void runCalibrationCases(StorageModule& storage, std::unique_ptr<Iterator>& iterator);
    /* Virtual functions required by class StorageUserModule */
    virtual void registerStorageNeeds(StorageRegistry& registry);
    virtual void registerMetadataNeeds(StorageRegistry& registry);
    /* Required build function to support ModuleFactory */
    static Module* build(std::string name);
  
    FridaExecutor(std::string name);
    virtual ~FridaExecutor();

    /** @brief Provide access to internal count of number of times the process was launched
     */
    size_t GetNumTestProcessesUsed() const { return _nProcessesStarted; }

private:    
    static size_t _instanceCounter;
    const std::string _instanceId; 
    
    /// Windows process flags (Like NEW_CONSOLE, NO_WINDOW etc.. )
    DWORD _processFlags;
    std::string _pipeName;
    std::string _traceBitsName;
    std::string _testName;
    std::string _sutCommandLine;
    ///sutArgv config options
    std::vector<std::string> _sut_argv;
    bool _ignore_hangs;
    OVERLAPPED _overlapped;
    HANDLE _hPipe;
    HANDLE _hJob;
    bool _debugLog;
    FILE *_sut_stdout_file;
    FILE *_sut_stderr_file;
    HANDLE _stdout;
    HANDLE _stderr;
    uint64_t _nTest;
    uint64_t _nTimeoutRaw;
    PROCESS_INFORMATION _pi;

    HANDLE _hMapFile;
    HANDLE _hTestFile;
    LPVOID _testDataShared;
    const DWORD _testDataMax = 1024 * 1024;

    size_t _nProcessesStarted; 

    ///Value indicating an untouched coverage word
    static const int PORCELAIN = 255;

    /* Default configuration values */
    ///Default map size value (65536)
    static const int FRIDA_MAP_SIZE = (1U << 16);
    ///Default for memoryLimitInMB (128MB)
    static const int DEFAULT_SUT_MB_LIMIT = 128;
    ///Default for alwaysWriteTraceBits (false)
    static const int DEFAULT_ALWAYS_TRACE = false;
    ///Default for traceBitsOnNewCoverage (true)
    static const int DEFAULT_COVERAGE_ONLY_TRACE = true;
    ///Default for writeStats (true)
    static const bool DEFAULT_WRITE_STATS = true;
    ///Default for debugLog (false)
    static const bool DEFAULT_DEBUG = false;

    ///Default timeout value (1000ms)
    static const int DEFAULT_TIMEOUT_MS = 1000; 

    ///Default start retry count 
    static const int DEFAULT_START_RETRY = 3; 

    /// Utility to inspect/manipulate AFL Coverage data
    AFLCoverageUtil cov_util;

    /* Various collections of coverage map data */
    ///Holds coverage data recorded from a single, most recent, run
    uint8_t* trace_bits = nullptr;
    ///Holds cumulative coverage over several runs for test cases that run normally
    uint8_t* virgin_trace = nullptr;
    ///Holds cumulative coverage over several runs for test cases that crash
    uint8_t* virgin_crash = nullptr;
    ///Holds cumulative coverage over several runs for test cases that hang
    uint8_t* virgin_hang = nullptr;
    ///Used to compare with new coverage bits to identify new coverage
    uint8_t* old_trace = nullptr;

    ///Total time taken
    unsigned time_taken = 0;

    size_t _start_retry;
    
    /* SUT run status variables */
    bool _sut_presumed_alive; // SUT is presumed to be running, used to flag abandoned tests that were finished 
    ///Return status from the SUT
    int sut_status = 0; /* Really test status */
    ///Exitcode from the SUT
    int sut_exitcode = 0;
    ///Set to a non-zero value if the SUT hangs
    int sut_hung = 0;
    ///Descriptor for Fuzzer to write test cases to
    int sut_test_write = 0;
    ///Descriptor for SUT to read test cases from
    int sut_test_read = 0;
    ///PID for forkserver to request SUT processes from
    int forkserver_pid = 0;
    /* Timeout values to catch a hanging SUT */
    ///The current timeout value
    unsigned int timeout_dur = 0;

    /* Keys/tags for storage */
    ///TEST_CASE handle
    int test_case_key;
    ///EXEC_TIME_US handle
    int exec_time_key;
    ///AFL_EXEC_STATUS handle
    int exec_status_key;
    ///AFL_TRACE_BITS handle, this field is conditionally registered for
    int trace_bits_key = -1;
    ///COVERAGE_COUNT handle
    int coverage_count_key;
    ///CRASHED tag
    int crashed_tag;
    ///HUNG tag
    int hung_tag;
    ///INCOMPLETE tag for liveness-only fuzzing
    int incomplete_tag;
    ///RAN_SUCCESSFULLY tag
    int normal_tag;
    ///HAS_NEW_COVERAGE tag
    int has_new_coverage_tag;
    ///TOTAL_BYTES_COVERED metadata handle
    int cumulative_coverage_metadata;

    /* Configuration Options */
    ///True if alwaysWriteTraceBits is set
    bool always_write_trace;
    ///True if traceBitsOnNewCoverage is set
    bool coverage_only_trace;
    ///True if writeStats is set
    bool write_stats;
    ///Map size in bytes
    unsigned int map_size;
    ///memoryLimitInMB config option
    int sut_mem_limit;

    /* Other internal helper functions */
    /**
     * @brief Configures internal options using configuration opertions
     * passed to this ExecutorModule from Module
     *
     * Configuration options include:
     * - Output directory
     * - Optional Manual Timeout (microseconds)
     * - Timeout Calibration thresholds/constants
     * - Debug logging
     */
    void loadConfig(ConfigInterface &config);
  
    /**
     * @brief First time start of SUT, 
     * test data.
     */
    bool startSUT();

    /**
     * @brief Function that ensures the SUT is started or restarted and read to receive 
     * test data.
     */
    bool restartSUT();

    /**
     * @brief Kills fokserver process group and releases
     * shared memory segments.
     */
    void releaseResources(void);

    /**
     * @brief Initializes pipes and resource limits for SUT
     */
    bool initSUTControl(void);

    /**
     * @brief Initializes the shared memory regions for coverage and test 
     * data
     */
    bool initSharedMemory(void);
  
    /**
     * @brief Dispatch testcase to SUT process and return when done
     *
     * @param buffer Fuzzer-generated testcase bytes
     * @param size Fuzzer-generated testcase size
     */
    void execTestCase(uint8_t *buffer, uint32_t size);

    /**
     * @brief wait for Results or crash and ensure sut is ready for next
     */
    void waitForResultsThenReady(uint32_t size);

    /**
     * @brief Identify SUT run status, accumulate SUT coverage bitmaps 
     */
    void handleStatus(StorageModule& storage, StorageEntry* entry);

    /**
     * @brief Examine coverage bitmap, write coverage related data to storage
     */
    void handleCoverageBitmap(StorageModule& storage, StorageEntry* entry);

    /**
     * @brief Helper method to write trace_bits_key, overwriting any existing value
     * The overwrite enables test cases to be executed again, if desired.
     */
    void writeOrOverwriteTraceBits(StorageModule& storage, StorageEntry* entry);

    /**
     * @brief Checks error value received from waitpid/forkserver to
     * determine if the SUT crashed
     *
     * @param status Status to be checked
     * @return bool Whether or not the status value corresponds to a crash
     */
    bool isCrash(int status);

};
}
