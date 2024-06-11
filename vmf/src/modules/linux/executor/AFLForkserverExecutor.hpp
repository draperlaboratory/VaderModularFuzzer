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

#include <unistd.h>
#include <stdbool.h>
#include <limits.h>

#include "AFLCoverageUtil.hpp"
#include "ExecutorModule.hpp"
#include "SimpleStorage.hpp"

#define MEM_BARRIER() __asm__ volatile("" ::: "memory")

namespace vmf
{

/**
 * @brief Module that uses AFL++ forkserver for running test cases
 */
class AFLForkserverExecutor : public ExecutorModule
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
  
    AFLForkserverExecutor(std::string name);
    virtual ~AFLForkserverExecutor();

protected:
    ///OK return status code
    static const int AFL_STATUS_OK = 0;
    ///HUNG return status code
    static const int AFL_STATUS_HUNG = 1;
    ///CRASHED return status code
    static const int AFL_STATUS_CRASHED = 2;
    ///ERROR return status code
    static const int AFL_STATUS_ERROR = 3;
    ///NOINST return status code
    static const int AFL_STATUS_NOINST = 4;
    ///NOBITS return status code
    static const int AFL_STATUS_NOBITS = 5;

    /* Errors values returned by a sanitizer-instrumented crashing SUT */
    ///Memory sanitizer error return value
    static const int MSAN_ERROR = 86;
    ///Leak sanitizer error return value
    static const int LSAN_ERROR = 23;

    /* Error values returned by forkserver shim */
    ///OPT_ERROR forkserver shim return status code
    static const int FS_OPT_ERROR = 0xf800008f;
    ///ERROR_MAP_SIZE forkserver shim return status code
    static const int FS_ERROR_MAP_SIZE = 1;
    ///ERROR_MAP_ADDR forkserver shim return status code
    static const int FS_ERROR_MAP_ADDR = 2;
    ///ERROR_SHM_OPEN forkserver shim return status code
    static const int FS_ERROR_SHM_OPEN = 4;
    ///ERROR_SHMAT forkserver shim return status code
    static const int FS_ERROR_SHMAT = 8;
    ///ERROR_MMAP forkserver shim return status code
    static const int FS_ERROR_MMAP = 16;
    ///ERROR_OLD_CMPLOG forkserver shim return status code
    static const int FS_ERROR_OLD_CMPLOG = 32;
    ///ERROR_OLD_CMPLOG_QEMU forkserver shim return status code
    static const int FS_ERROR_OLD_CMPLOG_QEMU = 64;

    /* Constant values indicating read/write ends of a pipe */
    ///Read pipe constant
    static const int READ_PIPE = 0;
    ///Write pipe constant
    static const int WRITE_PIPE = 1;

    ///Constant value for setenv to overwrite existing values
    static const int OVERWRITE = 1;

    ///File descriptot for the control pipe to the forkserver/SUT
    int CTRL_PIPE_WR = 0;
    ///File descriptor for the status pipe back from the forkserver/SUT
    int STAT_PIPE_RD = 0;
    ///Hard-coded SUT instrumentation value for control pipe
    static const int CTRL_PIPE_RD = 198;
    ///Hard-coded SUT instrumentation value for status pipe
    static const int STAT_PIPE_WR = 199; 

    ///Unique signature to write to coverage-map in the case of a failed exec (hard-coded SUT instrumentation value)
    static const uint32_t EXEC_FAIL = 0xfee1dead;

    ///Multiplyer to extend timeout when first starting forkserver
    static const int STARTUP_DELAY_MULT = 10;

    ///Value indicating an untouched coverage word
    static const int PORCELAIN = 255;

    ///Maximum number of attempts to retry testcase for hanging SUT
    static const int MAX_HANG_ATTEMPTS = 2;

    /* Default configuration values */
    ///Default map size value (65536)
    static const int DEFAULT_MAP_SIZE = (1U << 16);
    ///Default for memoryLimitInMB (128MB)
    static const int DEFAULT_SUT_MB_LIMIT = 128;
    ///Default for maxCalibrationCases (300)
    static const int DEFAULT_MAX_CALIB = 300;
    ///Default for alwaysWriteTraceBits (false)
    static const int DEFAULT_ALWAYS_TRACE = false;
    ///Default for traceBitsOnNewCoverage (true)
    static const int DEFAULT_COVERAGE_ONLY_TRACE = true;
    ///Default for writeStats (true)
    static const bool DEFAULT_WRITE_STATS = true;
    ///Default for debugLog (false)
    static const bool DEFAULT_DEBUG = false;
    ///Default timeout value in case we can't calibration (1000ms)
    static const int DEFAULT_TIMEOUT_MS = 1000; 
    ///Lower bound timeout value (20ms)
    static const int TIMEOUT_LOWER_BOUND = 20;
    ///Upper bound timeout value (1000ms)
    static const int TIMEOUT_UPPER_BOUND = 1000;
    ///Default for useASAN (false)
    static const bool DEFAULT_USE_ASAN = false;
    ///Default for useLSAN (false)
    static const bool DEFAULT_USE_LSAN = false;
    ///Default for useMSAN (false)
    static const bool DEFAULT_USE_MSAN = false;
    ///Default for useUBSAN (false)
    static const bool DEFAULT_USE_UBSAN = false;

    ///Timeout for expected automatic responses from Forkserver/SUT (10s)
    static const int NOBLOCK_LONG_TIMEOUT = 10000;

    /* SUT sanitizer options */
    ///Address sanitizer option
    bool use_asan = false;
    ///Leak sanitizer option
    bool use_lsan = false;
    ///Memory sanitizer option
    bool use_msan = false;
    ///Undefined behavior sanitizer option
    bool use_ubsan = false;

    /// Maximum attempts to write to file/pipe
    static const int MAX_WRITE_ATTEMPTS = 5;

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

    ///Identifier for shared memory that records SUT coverage
    int shm_id = 0;

    ///Filename for temporary file for testcase
    char testcase_file[PATH_MAX];
    ///Temporary file to connect fuzzer/forkserver for testcase delivery
    int testcase_fd = 0;

    /* Records for calibrating test case execution times */
    ///Total time taken
    unsigned time_taken = 0;
    ///The maximum time taken
    unsigned max_time = 0;
    ///Total time taken for all test cases during calibration
    int sum_time = 0;

    /* SUT run status variables */
    ///Return status from the SUT
    int sut_status = 0;
    ///Exitcode from the SUT
    int sut_exitcode = 0;
    ///Set to a non-zero value if the SUT hangs
    int sut_hung = 0;
    ///Process id of the SUT execution process
    int sut_pid = 0;
    ///Descriptor for Fuzzer to write test cases to
    int sut_test_write = 0;
    ///Descriptor for SUT to read test cases from
    int sut_test_read = 0;
    ///PID for forkserver to request SUT processes from
    int forkserver_pid = 0;
    /* Timeout values to catch a hanging SUT */
    ///The current timeout value
    int timeout_dur = 0;
    ///The timeout to use on a first attempt to run the SUT
    int timeout_short = 0;
    ///The timouet to use on a second attempt to run the SUT
    int timeout_long = 0;

    ///Number of calibration tests
    int num_calib = 0;
    ///Flag that we've established timeouts
    bool calibrated = false;

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
    ///RAN_SUCCESSFULLY tag
    int normal_tag;
    ///HAS_NEW_COVERAGE tag
    int has_new_coverage_tag;
    ///MAP_SIZE metadata handle
    int map_size_key;
    ///CALIBRATED_TIMEOUT metadata handle
    int calib_timeout_key;
    ///TOTAL_BYTES_COVERED metadata handle
    int cumulative_coverage_metadata;

    /* CmpLog */
    ///CMPLOG_MAP_BITS handle, only registered for if cmplog is enabled
    int cmpLogMapKey = -1;
    ///Flag indicating whether or not cmplog is enabled
    bool cmp_log_enabled = false;
    ///Shared memory id for cmplog data region
    int cmplog_shm_id = 0;
    ///Pointer to cmplog data
    uint8_t* cmplog_bits = nullptr;

    /* Configuration Options */
    ///True when timeoutInMs manual timeout value was specified
    bool use_manual_timeout;
    ///True if alwaysWriteTraceBits is set
    bool always_write_trace;
    ///True if traceBitsOnNewCoverage is set
    bool coverage_only_trace;
    ///True if writeStats is set
    bool write_stats;
    ///timeoutInMs manual timeout value
    int manual_timeout_ms;
    ///Map size in bytes
    int map_size;
    ///sutArgv config options
    std::vector<std::string> sut_argv;
    ///memoryLimitInMB config option
    int sut_mem_limit;
    ///True for stdin interface
    int sut_use_stdin;
    ///File handle for sut stdout
    int sut_stdout;
    ///File handle for sut stderr
    int sut_stderr;
    ///maxCalibrationCases config option
    int max_calib;
    ///customExitCode config option
    int custom_exitcode;
    ///True if a custom exit code is set
    bool use_custom_exitcode;

    /* Other internal helper functions */
    /**
     * @brief Configures internal options using configuration opertions
     * passed to this ExecutorModule from Module
     *
     * Configuration options include:
     * - Output directory
     * - Optional Manual Timeout (milliseconds)
     * - Timeout Calibration thresholds/constants
     * - SUT path and command line arguments (argv)
     * - Resource limit (Memory, MB) for forked processes
     * - Debug logging
     */
    void loadConfig(ConfigInterface &config);
  
    /**
     * @brief Function that calls fork and coordinates parent
     * (forkserver), child (SUT) execution.
     */
    bool startForkserver();

    /**
     * @brief Kills fokserver process group and releases
     * shared memory segments.
     */
    void releaseResources(void);

    /**
     * @brief Initializes pipes to communicate with forkserver/SUT
     */
    bool initFuzzerSUTIO(void);

    /**
     * @brief Configures IO for the fuzzer following the fork
     */
    void initFuzzerIO();
  
    /**
     * @brief Initializes the coverage maps and shared memory region where coverage
     * data is updated
     */
    bool initCoverageMaps(void);
  
    /**
     * @brief Verify SUT status ensuring it launched succesfully 
     */
    int checkSUT(void);

    /**
     * @brief Read SUT status from status pipe
     * @param result pointer to where the read status value is placed
     * @param timeout_ms a timeout value that's specified in milliseconds.
     * Setting this value to 0 will disable the timer and may hang indefinitely.
     *
     * @return int number of bytes read frmo the status pipe
     */
    int readStatus(int* result, int timeout_ms);

    /**
     * @brief Write to pipe/file and retry if interrupted
     * @param fd File descriptor to write to
     * @param buf Pointer to data to write
     * @param size Byte-count to be written
     *
     * @return int Number of bytes written to descriptor
     */
    int checkedWrite(int fd, uint8_t* buf, int size);

    /**
     * @brief Following the delivery of a test case to the SUT, read its pid and status
     *
     * @return int SUT execution status 
     */
    int getSUTStatus(void);
  
    /**
     * @brief Encloses code to spawn SUT post forkserver fork
     */
    void initSUT();
  
    /**
     * @brief Establishes pipes and shared memory bitmaps to interface with SUT
     */
    bool initSUTIO();

    /**
     * @brief Configure SUT process hardware resource limits
     */
    void setResourceLimits(void);

    void initSUTEnv();
    void initSANEnv();
    void getASANOptions(std::string& options);
    void getLSANOptions(std::string& options);
    void getMSANOptions(std::string& options);
    void getUBSANOptions(std::string& options);

    /**
     * @brief Attempt to autodetect the map size in the binary by running it with AFL_DEBUG=1
     * and parsing the results. Returns the size if it finds one and 0 otherwise.
     */
    int getSUTMapSize(void);

    /**
     * @brief Launch SUT binary via exec
     *
     */
    bool launchSUT();

    /**
     * @brief Implements forkserver-specific SUT dispatch. Clears
     * trace bits, delivers testcase to the forkserver and requests a
     * new SUT process from the forkserver, records execution time,
     * and interprets execution status.
     *
     * @param buffer Fuzzer-generated testcase bytes
     * @param size Fuzzer-generated testcase size
     */
    void runOnForkserver(uint8_t *buffer, int size);

    /**
     * @brief Dispatch testcase to SUT process
     *
     * @param buffer Fuzzer-generated testcase bytes
     * @param size Fuzzer-generated testcase size
     */
    bool deliverTestCase(uint8_t *buffer, int size);

    /**
     * @brief Request a new SUT process from Fork-server
     */
    bool requestProcess(void);

    /**
     * @brief Start a timer, and wait+read SUT execution status.
     */
    void waitSUT(void);

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
     * @brief Update SUT execution status and detect errors
     */
    void updateStatus(void);

    /**
     * @brief Checks error value received from waitpid/forkserver to
     * determine if the SUT crashed
     *
     * @param status Status to be checked
     * @return bool Whether or not the status value corresponds to a crash
     */
    bool isCrash(int status);

    /**
     * @brief Checks and extracts error code from forkserver
     *
     * @param error Possible error code
     * @return Returns the packed error code
     */
    int getFSError(int error);

    /**
     * @brief Verifies that core-dumps are not being sent to an external
     * utility, which reduces performance.
     */
    bool verifyCorePattern(void);

    /**
     * @brief Calculate timeout values based on the metrics collected
     * during calibration testing
     *
     * @param avg_time Average execution time of calibration tests
     * @param max_time Longest test execution time recorded during calibration
     * @param sum_time Total test execution time of all calibration tests
     */
    static int calculateTimeout(unsigned avg_time, unsigned max_time, unsigned sum_time);

    /**
     * @brief Calculate, update and report timeout values following
     * calibration testing.
     *
     * @param max_time Longest test execution time recorded during calibration
     * @param sum_time Total test execution time of all calibration tests
     */
    void calibrateTimeout(unsigned max_time, unsigned sum_time);

    /**
     * @brief Simple formulate to produce the long (second-attempt)
     * timeout given a short timeout
     *
     * @param timeout Short timeout value that's applied to a formula to
     * calculate the long timeout
     * @return int Calculated long timeout value
     */
    static int calculateLongTimeout(int timeout);

    /**
     * @brief Update internal timeout values from the provided (short)
     * timeout
     *
     * @param timeout Short timeout used to update internal short, long,
     * current timeout values
     */
    void setTimeouts(int timeout);

    /**
     * @brief Kill the SUT process spawned by the forkserver,
     * and let the forkserver know
     */
    void killSUT(void);

    /**
     * @brief Check that we have a calibrated timeout, and find one in
     * storage if we don't
     *
     * @param storage Reference to storage to possible lookup a
     * timeout value
     */
    void checkTimeout(StorageModule &storage);
};
}
