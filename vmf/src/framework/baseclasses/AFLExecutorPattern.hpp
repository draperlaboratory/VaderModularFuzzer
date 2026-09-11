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

#include "ExecutorModule.hpp"
#include "StorageModule.hpp"

namespace vmf {

/**
* @brief Helper class for implementing executors for AFL++
* source-based instrumented SUTs.
*
* This class cannot be used as an executor on its own, as it does not
* implement the runTestCase method.  Rather, it provides helper
* methods that can be used as the basis of implementing an executor.
*/
class AFLppSrcExecutorPattern : public ExecutorModulePattern {
public:

    /**
     * @brief Calls a configuration loader, parses AFL++ preample and
     * launches the forkserver
     */
    virtual void init(ConfigInterface& config);

    /**
     * @brief Inherited from ExecutorModulePattern
     */
    virtual void runTestCase(StorageModule& storage, StorageEntry* entry);

    /**
     * @brief Inherited from ExecutorModulePattern
     */
    virtual void runCalibrationCases(StorageModule& storage, std::unique_ptr<Iterator>& iterator);

    /**
     * @brief Inherited from ExecutorModulePattern
     */
    virtual void registerStorageNeeds(StorageRegistry& registry);

    /**
     * @brief Inherited from ExecutorModulePattern 
     */
    virtual void registerMetadataNeeds(StorageRegistry& registry);

protected:

    /**
     * @brief Verifies timeouts are set and resets single-run timer
     * 
     * @param storage 
     * @return entry the entry to execute
     */
    virtual void preDispatch(StorageModule& storage, StorageEntry* entry);

    /**
     * @brief Delivers the testcase to the forkserver, launches it,
     * bounds execution, and captures execution status
     * 
     * @param storage 
     * @param entry the entry to execute
     */
    virtual void dispatchTestCase(StorageModule& storage, StorageEntry* entry);

    /**
     * @brief Updates storage with data from executing the current testcase
     * 
     * @param storage 
     * @param entry the entry to execute
     */
    virtual void postDispatch(StorageModule& storage, StorageEntry* entry);
    
private:


    /**
     * @brief Adds configurations for AFL++ debug, map size
     * 
     * @param config
     */
    void loadConfig(ConfigInterface &config);

    /* Interactions with SUT */
    /**
     * @brief Reads data from the forkserver's status pipe
     * 
     * @param result Data fetched from the status pipe
     * @param timeout_ms Timeout in MS to wait for data on the status pipe
     * @param max_bytes Maximum number of bytes to fetch from the status pipe
     */
    int readStatus(int* result, int timeout_ms, int max_bytes);

    /**
     * @brief Kills the SUT currently executing a testcase
     *
     * @param sut_pid PID of the process to kill
     */
    void killSUT(int sut_pid);

    /**
     * @brief Launch a new process that runs the forkserver. This sets
     * up all the necessary communication vectors between the
     * executor, forkserver and SUT, including the shared memory
     * and status and control pipes.
     */
    bool startForkserver(void);

    /**
     * @brief Frees any resources collected by the executor such as
     * shared memory regions, pipes, and child processes.
     */
    void releaseResources(void);

    /* Forkserver handshake */
    /**
     * @brief Given a forkserver handshake message, determine which
     * features are being used, and fetch that data from the status pipe
     * 
     * @param
     */
    void processFSOptions(int msg);

    /**
     * @brief Given a legacy AFL++ forkserver (<4.20c) handshake
     * message, determine which features are being used, and fetch
     * that data from the status pipe
     * 
     * @param
     */
    void processFSOptionsLegacy(int msg);

    /**
     * @brief Given a forkserver handshake message that contains
     * version information, parse it and return the version
     * 
     * @param msg Handshake message containing version information
     * @return forkserver version
     */
    int processFSVersion(int msg);

    /**
     * @brief Given a forkserver handshake message that contains
     * map size information, parse it and return the map size
     * 
     * @param msg Handshake message containing map size information
     * @return map size in bytes
     */
    int processMapSizeMsg(int msg);

    /**
     * @brief Shrink the map size given a new size. Shrinking the
     * shared memory region containing runtime data to the precise
     * size used by the forkserver increases performance by reducing
     * overhead from copying unused bytes.
     * 
     * @param new_size New map size in bytes
     */
    void shrinkMapSize(unsigned int new_size);

    /**
     * @brief Receive the map size over the status pipe and update the
     * size of the shared memory holding runtime data
     */
    void receiveMapSize(void);

    /**
     * @brief Receive the autodict, a set of strings identified in the
     * SUT that are expecetd to be useful for fuzzing.
     */
    void receiveAutoDict(void);

    /**
     * @brief Respond to the forkserver with a handshake message
     * containing the forkserver version
     * 
     * @param msg Response message containing the forkserver version XOR'ed with all 1s. 
     */
    void handshakeResp(int msg);

    /**
     * @brief Perform the handshake with the recently spawned
     * forkserver to gather version, mapsize, and data for other features
     */
    bool handshakeFS(void);

    /* Initialize forkserver and SUT environment */
    /**
     * @brief Initialize communication channels between the executor,
     * forkserver and SUT
     */
    void initFuzzerSUTIO(void);

    /**
     * @brief Initialize the forkserver process by setting up the IO,
     * environment and resource limits
     * 
     * @param
     */
    void initSUT(void);

    /**
     * @brief Initialize communication channels in the fuzzer process
     * 
     * @param
     */
    void initFuzzerIO(void);

    /**
     * @brief Initialize communication channels in the forkserver
     * process
     * 
     * @return success or failure to intialize communication channels
     */
    bool initSUTIO(void);
    
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

    /* Error values returned by forkserver shim */
    ///OPT_ERROR forkserver shim return status code
    static const int FS_OPT_ERROR = 0xf800008f;
    ///Prefix for non-legacy forkserver initial handhsake message
    static const int FS_VERSION_PREFIX = 0x41464c00;
    ///Mask for version information in initial forkserver handshake message
    static const int FS_VERSION_MASK = 0x000000ff;
    ///Mask for forkserver handshake message mapsize option
    static const int FS_OPT_MAPSIZE = 0x00000001; // AFL++ 4.20 FS_NEW_OPT_MAPSIZE
    ///Mask for forkserver handshake message shared-mem test input option
    static const int FS_OPT_SHMTESTDELIV = 0x00000002; // AFL++ 4.20 FS_NEW_OPT_SHDMEM_FUZZ
    ///Mask for forkserver handshake message auto dictionary option
    static const int FS_OPT_AUTODICT = 0x00000800; // AFL++ 4.20 FS_NEW_OPT_AUTODICT
    ///Mask for bits indicating available forkserver options in handshake message (Legacy)
    static const int FS_OPT_ENABLED_L = 0x80000001; 
    ///Forkserver option indicating use of snapshot feature (Legacy)
    static const int FS_OPT_SNAPSHOT_L = 0x20000000;
    ///Forkserver option indicating use of shared-mem for testcase delivery (Legacy)
    static const int FS_OPT_SHMTESTDELIV_L = 0x01000000; // AFL++ 4.20 FS_OPT_SHDMEM_FUZZ 
    ///Mask for forkserver handshake message with actual mapsize (Legacy)
    static const int FS_OPT_MAPSIZE_L = 0x40000000;
    ///Forkserver option indicating use of auto dictionary (Legacy)
    static const int FS_OPT_AUTODICT_L = 0x10000000;
    ///Mask for forkserver handshake message with actual mapsize (Legacy)
    static const int FS_OPT_MAPSIZE_VALUE_L = 0x00fffffe; // AFL++ 4.20 FS_OPT_MAX_MAPSIZE
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

    ///File descriptor for the control pipe to the forkserver/SUT
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

    /* Default configuration values */
    ///Default map size value (8MiB)
    static const int DEFAULT_MAP_SIZE = (8 * (1U << 20));
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
  
    ///Timeout for expected automatic responses from Forkserver/SUT (10s)
    static const int NOBLOCK_LONG_TIMEOUT = 10000;

    ///Maximum size for shared mem region. First 4 bytes hold data size.
    static const int SHARED_MEM_REGION_SIZE = 1024000;
    ///Maximum size for shared mem test case
    static const int SHARED_MEM_MAX_SIZE = SHARED_MEM_REGION_SIZE - sizeof(int32_t);

    //Signatures used by AFL++ to indicate special fuzzing features present in binary
    ///Persist-mode signature
    static constexpr const char* PERSIST_SIG = "##SIG_AFL_PERSISTENT##";
    ///Deferred init signature
    static constexpr const char* DEFER_SIG = "##SIG_AFL_DEFER_FORKSRV##";

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
    ///Holds testcase data when using shared memory testcase delivery
    uint8_t* shared_mem_testcase_buff = nullptr;

    ///Identifier for shared memory that records SUT coverage
    int shm_id = 0;

    ///Identifier for shared memory that is used for shared mem testcase delivery
    int shm_testcase_id = 0;
    ///Points to the first 4 bytes in the overloaded shared memory region, holds the size
    uint32_t* shm_testcase_len;

    ///Filename for temporary file for testcase
    char testcase_file[PATH_MAX];
    ///Temporary file to connect fuzzer/forkserver for testcase delivery
    int testcase_fd = 0;

    ///EXEC_STATUS handle
    int exec_status_key;
    ///COVERAGE_COUNT handle
    int coverage_count_key;
    ///HAS_NEW_COVERAGE tag
    int has_new_coverage_tag;
    ///TOTAL_BYTES_COVERED metadata handle
    int cumulative_coverage_metadata;
    
    /* Values read from AFL_DEBUG info */
    ///map size read from debug info
    unsigned int map_size_from_debug_info = 0;
    ///Major version read from debug info (eg 4 in 4.30c)
    int major_version;
    ///Minor version read from debug info (eg 30 in 4.30c)
    int minor_version;

    /* Configuration Options */
    bool always_write_trace;
    ///True if traceBitsOnNewCoverage is set
    bool coverage_only_trace;
    ///True if writeStats is set
    bool write_stats;
    ///memoryLimitInMB config option
    int sut_mem_limit;
    ///True for stdin interface
    int sut_use_stdin;
    ///True for shared-mem test delivery
    bool sut_shm_test = false;
    ///File handle for sut stdout
    int sut_stdout;
    ///File handle for sut stderr
    int sut_stderr;
    ///True if additional AFL debug info should be printed
    bool enable_afl_debug = false;

    //Special fuzzing modes detected by signatures in the binary
    ///Binary has persistent mode signature
    bool is_persistent_mode_binary = false;
    ///Binary has deferred init signature
    bool is_deferred_init_binary = false;
    ///Binary has shared memory delivery mode signature
    bool is_shared_mem_binary = false;
