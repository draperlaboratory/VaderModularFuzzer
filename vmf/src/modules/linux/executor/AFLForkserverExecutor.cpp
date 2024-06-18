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

#include <algorithm>
#include <array>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <string>

#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ipc.h>
#include <sys/shm.h>

#include "AFLFeedback.hpp"
#include "AFLForkserverExecutor.hpp"
#include "Logging.hpp"
#include "ModuleFactory.hpp"
#include "VmfUtil.hpp"

#include "RedPawnCmpLogMap.hpp"

using namespace vmf;
REGISTER_MODULE(AFLForkserverExecutor);

/**
 * @brief Builder method
 * 
 * @param name the module name
 * @return Module* the newly constructed module instance
 */
Module *AFLForkserverExecutor::build(std::string name) {
    return new AFLForkserverExecutor(name);
}


void AFLForkserverExecutor::releaseResources() {
  /* Fetch forkserver group ID */
  int pgrp = getpgid(forkserver_pid);
  /* Kill all processes in that group */
  if (pgrp > 0) killpg(pgrp, SIGTERM);
  /* Kill the forkserver */
  kill(forkserver_pid, SIGTERM);

  /* Release shared memory */
  shmctl(shm_id, IPC_RMID, NULL);
  if (cmp_log_enabled)
    shmctl(cmplog_shm_id, IPC_RMID, NULL);

  /* Now kill forkserver and its child processes after giving them
     the chance to terminate gracefully */
  /* Kill all processes in that group */
  if (pgrp > 0) killpg(pgrp, SIGKILL);
  /* Kill the forkserver */
  kill(forkserver_pid, SIGKILL);

  delete[] virgin_trace;
  delete[] virgin_hang;
  delete[] virgin_crash;
}

/**
 * @brief Construct a new AFLForkserverExecutor object
 * 
 * @param name the module name
 */
AFLForkserverExecutor::AFLForkserverExecutor(std::string name) :
    ExecutorModule(name), cov_util() {
}

AFLForkserverExecutor::~AFLForkserverExecutor() {
    releaseResources();
}

void AFLForkserverExecutor::init(ConfigInterface& config) {
    loadConfig(config);
    verifyCorePattern();

    /* Pick map size to use based on both auto detected size and manual configuration */
    int auto_map_size = getSUTMapSize();
    if (map_size == 0) {
        /* If no configured size, use autodetection if it worked and DEFAULT_MAP_SIZE otherwise*/
        if (auto_map_size != 0) {
            map_size = auto_map_size;
            LOG_INFO << "Map size autodetection succeeded. Using size " << map_size << ".";
        } else {
            map_size = DEFAULT_MAP_SIZE;
            LOG_WARNING << "Unable to automatically detect map size and no size specified. Using default of " << map_size << ".";
        }
    } else {
        /* If configured a size, issue warning if different from auto detected size */
        if (map_size != auto_map_size && auto_map_size != 0) {
            LOG_WARNING << "Using manually configured map size of " << map_size << " but autodetection found size " << auto_map_size;
        } else {
            LOG_INFO << "Using map size of " << map_size;
        }
    }

    if (!startForkserver())
        throw RuntimeException("Failed to launch SUT", RuntimeException::UNEXPECTED_ERROR);
}

bool AFLForkserverExecutor::verifyCorePattern(void) {
    /* Check that the core dump pattern does not begin with a pipe.
       This causes crashes to be sent to an external utility, which is very slow
       and causes VMF to misinterpret them as timeouts. As such, this is a fatal error. */
    int corepattern_fd = open("/proc/sys/kernel/core_pattern", O_RDONLY);

    if (corepattern_fd < 0)
        throw RuntimeException("Unable to open /proc/sys/kernel/core_pattern for reading.\n",
                               RuntimeException::UNEXPECTED_ERROR);
    char firstChar;
    if (read(corepattern_fd, &firstChar, 1) == 1 && firstChar == '|')
        throw RuntimeException("\nYour system is configured to send core dump notifications "
                               "to an external utility.\nThis is slow and causes crashes "
                               "to be misinterpreted as timeouts.\nTo fix, please log in as root "
                               "and run the following command: \n"
                               "    echo core >/proc/sys/kernel/core_pattern",
                               RuntimeException::UNEXPECTED_ERROR);
    return true;
}

void AFLForkserverExecutor::checkTimeout(StorageModule &storage) {
    /* We're done if we're already calibrated */
    if (calibrated) return;

    /* Check if another executor recorded their timeout as metadata */
    StorageEntry& metadata = storage.getMetadata();
    int timeout = metadata.getIntValue(calib_timeout_key);
    if (!timeout)
        throw RuntimeException("Couldn't find a timeout value",
                               RuntimeException::UNEXPECTED_ERROR);
    /* Update the internal timeouts using the found value */
    setTimeouts(timeout);
    /* Remember that we're calibrated */
    calibrated = true;
}

void AFLForkserverExecutor::runTestCase(StorageModule& storage, StorageEntry* entry) {
    /* Fetch fuzzer-generated input bytes and size from entry */
    int size = entry->getBufferSize(test_case_key);
    uint8_t* buffer = reinterpret_cast<uint8_t*>(entry->getBufferPointer(test_case_key));

    /* Make sure we're calibrated to run a test case with a timeout */
    checkTimeout(storage);

    /* Run the test */
    runOnForkserver(buffer, size);

    /* Record execution stats */
    handleStatus(storage, entry);
}

void AFLForkserverExecutor::runOnForkserver(uint8_t *buffer, int size) {
    /* Counter for attempts retrying a hanging testcase */
    int attempts = 0;

    /* Reset timeout and hung flag */
    timeout_dur = timeout_short;

    /* Retry if the SUT hangs */
    do {
        /* Reset SUT hung status flag */
        sut_hung = 0;

        /* Clear previous run's coverage trace */
        memset(trace_bits, 0, map_size);
        if (cmp_log_enabled)
            memset(cmplog_bits, 0, sizeof(struct cmp_map));
        /* Prevent the compiler from delaying the memset */
        MEM_BARRIER();

        /* Deliver the new test case to the forkserver */
        if (!deliverTestCase(buffer, size)) {
            LOG_ERROR << "Failed to deliver test case to SUT";
            return;
        }
        /* Tell the forkserver to launch the test */
        if (!requestProcess()) {
            LOG_ERROR << "Failed to request a new process from the forkserver";
            return;
        }

        /* Record the SUT's execution-time for this testcase */
        uint64_t start_time = VmfUtil::getCurTime();

        /* Listen to the forkserver for SUT completion */
        waitSUT();

        /* Record the time after the SUT returns its execution status */
        uint64_t end_time = VmfUtil::getCurTime();

        /* Calculate the duration in microseconds, first in 64 bits.
           Make sure end time is larger than start_time. */
        uint64_t time_taken_long;
        if (end_time > start_time)
        {
            time_taken_long = end_time - start_time;
        } else
        {
            //This has been observed to occur in docker
            LOG_WARNING << "End time was before start time. Using an exec time of 1 us.";
            time_taken_long = 1;
        }

        /* Limit time_taken to what we can fit in target data type (signed int) */
        if (time_taken_long > (uint64_t) INT_MAX)
        {
            //This would only happen if the SUT takes longer than 35 minutes to execute,
            //which likely indicates another problem.
            LOG_ERROR << "Execution time overflowed data type, capping to max value.";
            time_taken_long = (uint64_t) INT_MAX;
        }

        /* Cast to int, can't overflow because max value is INT_MAX */
        time_taken = (int) time_taken_long;

        /* The compiler shouldn't move trace_bits operations below this point */
        MEM_BARRIER();

        /* Identify SUT execution status */
        updateStatus();

        /* Retry a limited number of times */
        if (sut_hung == 1) attempts++;
        /* If we ran to completion, crashed, or hung twice, exit the loop */
        else break;
    } while (attempts < MAX_HANG_ATTEMPTS);
}

int AFLForkserverExecutor::checkedWrite(int fd, uint8_t* buf, int size) {
    int total = 0;
    int offset = 0;
    int remaining = size;
    int attempts = 0;
    do { /* Retry when interrupted */
        int wrote = write(fd, buf+offset, remaining);
        /* Cumulate amount written */
        total += wrote;
        /* Check for incomplete the write */
        if ((wrote != remaining) && (wrote > 0) && (total != wrote)) {
            if (wrote > 0) { /* Check for forward progress */
                /* Update ofsset by amount written */
                offset += wrote;
                /* Reduce remaining amount to be written */
                remaining -= wrote;
                attempts++;
            } else {
                throw RuntimeException("Failed to write to pipe/file",
                                       RuntimeException::UNEXPECTED_ERROR);
            }
        } else {
            break;
        }
    } while (attempts < MAX_WRITE_ATTEMPTS);
    return total;
}

bool AFLForkserverExecutor::deliverTestCase(uint8_t *buffer, int size) {
    /* Set seek to the beginning of the file */
    lseek(sut_test_write, 0, SEEK_SET);
    /* Write the test case to the file */
    int res = checkedWrite(sut_test_write, buffer, size);
    
    /* Trim the buffer in case the last test case was larger */
    if (ftruncate(sut_test_write, size) != 0)
        throw RuntimeException(
            "Forkserver failed to resize file forbuffer test case delivery",
            RuntimeException::UNEXPECTED_ERROR);
    /* Reset seek to the beginning of the file after write */
    lseek(sut_test_write, 0, SEEK_SET);

    return (res == size);
}
bool AFLForkserverExecutor::requestProcess(void) {
    /* Write 4-byte on the timeout status of the last run to the
       control pipe to request that the forkserver spawn a SUT
       process */
    if (checkedWrite(CTRL_PIPE_WR,
                     reinterpret_cast<uint8_t*>(&sut_hung),
                     4) != 4) {
        LOG_ERROR << "Unable to request new process from forkserver";
        return false;
    }

    return true;
}

int AFLForkserverExecutor::getFSError(int error) {
    if (error & FS_OPT_ERROR)
        return (error & 0x00ffff00) >> 8;
    else
        return 0;
}

void AFLForkserverExecutor::waitSUT(void) { 
    /* We'll read the SUT's status twice. The forkserver will first
       return the spawned SUT's pid, then its execution status. */
    if (readStatus(&sut_pid, NOBLOCK_LONG_TIMEOUT) != 4)
        throw RuntimeException("Malformed PID returned from forkserver.",
                               RuntimeException::UNEXPECTED_ERROR);

    if (sut_pid <= 0) {
        if (getFSError(sut_pid) == FS_ERROR_SHM_OPEN)
            throw RuntimeException("SUT reported failed shared mem access."
                                   "Perhaps increase available shared memory?",
                                   RuntimeException::UNEXPECTED_ERROR);
        else
            throw RuntimeException("Malformed PID returned from forkserver.",
                                   RuntimeException::UNEXPECTED_ERROR);
    }

    if ((readStatus(&sut_exitcode, timeout_dur) != 4) && (!sut_hung))
        throw RuntimeException("Malformed SUT status returned from forkserver.",
                               RuntimeException::UNEXPECTED_ERROR);
}

void AFLForkserverExecutor::handleStatus(StorageModule& storage, StorageEntry *entry) {

    /* Update status-specific metadata */
    switch (sut_status) {
        case AFL_STATUS_HUNG:
            entry->addTag(hung_tag);
            /* Update pointer to compare hanging cumulative  coverage */ 
            old_trace = virgin_hang;
            break;
        case AFL_STATUS_CRASHED:
            entry->addTag(crashed_tag);
            /* Update pointer to compare crashing cumulative coverage */ 
            old_trace = virgin_crash;
            break;
        case AFL_STATUS_OK:
            entry->addTag(normal_tag);
            /* Update pointer to compare general cumulative coverage */ 
            old_trace = virgin_trace;
            break;
        case AFL_STATUS_ERROR:
        default:
            throw RuntimeException("Forkserver encountered an unknown error",
                                   RuntimeException::UNEXPECTED_ERROR);
            break;
    }

    /* Record SUT execution time */
    entry->setValue(exec_time_key, static_cast<int>(time_taken));

    /* Check for new coverage, write new coverage tag and coverage bits to storage, as relevant*/
    handleCoverageBitmap(storage,entry);

    // Add cmplog map if enabled
    if (cmp_log_enabled)
    {
        char * cmpMapBits = entry -> allocateBuffer(cmpLogMapKey, sizeof(struct cmp_map));
        memcpy(cmpMapBits, cmplog_bits, sizeof(struct cmp_map));
    }
}

void AFLForkserverExecutor::handleCoverageBitmap(StorageModule& storage, StorageEntry* entry)
{
    StorageEntry& metadata = storage.getMetadata();
    int new_coverage = 0;

    /* If we always write the trace bits, then no need to skim */
    if (always_write_trace)
    {
        /* Classify coverage bitmap */
        cov_util.classifyCounts(trace_bits, map_size);
        
        writeOrOverwriteTraceBits(storage,entry);

        new_coverage = cov_util.hasNewBits(trace_bits, old_trace, map_size);

    } else {

        /* If we don't always write the bits, then do fast skim to possibly save work of classifying */
        int skim_found = cov_util.skim(reinterpret_cast<uint64_t*>(old_trace),
                                       reinterpret_cast<uint64_t*>(trace_bits),
                                       reinterpret_cast<uint64_t*>(trace_bits+map_size));

        if (skim_found)
        {
            /* Classify coverage bitmap */
            cov_util.classifyCounts(trace_bits, map_size);

            /* Check the appropriate cumulative (virgin) coverage map for new coverage */
            new_coverage = cov_util.hasNewBits(trace_bits, old_trace, map_size);
        }
    }

    /* Update Storage if we have new coverage */
    if (new_coverage)
    {

        entry->addTag(has_new_coverage_tag);

        /* Expensive Compute for coverage byte count */
        entry->setValue(coverage_count_key, static_cast<int>(cov_util.countBytes(trace_bits, map_size)));

        /* Write classified coverage bits, if the coverage_only_trace flag was set.
         * Skip this if always_write-trace is also set, because the bits have then already been written */
        if(coverage_only_trace && !always_write_trace)
        {
            writeOrOverwriteTraceBits(storage,entry);
        }
    
        /* Calculate cumulative coverage over all test cases so far */
        if (write_stats)
        {
            int cumulative_coverage = cov_util.countNon255Bytes(virgin_trace, map_size);
            metadata.setValue(cumulative_coverage_metadata, cumulative_coverage);
        }
    }

}

void AFLForkserverExecutor::writeOrOverwriteTraceBits(StorageModule& storage, StorageEntry* entry)
{
    char* buf;
    if (entry->hasBuffer(trace_bits_key))  //allows test case to be re-run, if need be
        buf = entry->getBufferPointer(trace_bits_key);
    else
        buf = entry->allocateBuffer(trace_bits_key, map_size);

    memcpy(buf, trace_bits, map_size);
}

void AFLForkserverExecutor::updateStatus(void) {
    if (sut_hung) { /* Check for timeout */
        timeout_dur = timeout_long;
        killSUT();
        sut_status = AFL_STATUS_HUNG;
        return;
    } else if (*reinterpret_cast<uint32_t*>(trace_bits) == EXEC_FAIL) {
        /* Forkserer failed fork a new SUT instance */
        sut_status = AFL_STATUS_ERROR;
        throw RuntimeException("Forkserver encountered an unknown error",
                               RuntimeException::UNEXPECTED_ERROR);
    } else if (isCrash(sut_exitcode)) {
        // LOG_DEBUG << "SUT Crashed";
        sut_status = AFL_STATUS_CRASHED;
    } else {
        // LOG_DEBUG << "SUT ran to completion";
        sut_status = AFL_STATUS_OK;
    }
}

bool AFLForkserverExecutor::isCrash(int status) {
    bool crashed = false;
    /* Normal Crash/Abort */
    crashed = WIFSIGNALED(status) /* Normal crash/abort */
        || (WEXITSTATUS(status) == MSAN_ERROR) /* Abort due to MSAN */
        || (WEXITSTATUS(status) == LSAN_ERROR);  /* Abort due to LSAN */
    /* Custom error code */
    crashed |= (use_custom_exitcode && (WEXITSTATUS(status) == custom_exitcode));

    return crashed;
}

void AFLForkserverExecutor::loadConfig(ConfigInterface &config) {
    std::string output_dir = config.getOutputDir() + "/forkserver";
    VmfUtil::createDirectory(output_dir.c_str());
    /* Configure SUT arguments */
    sut_argv = config.getStringVectorParam(getModuleName(),"sutArgv");

    /* Detect stdin vs. file-based SUT test case delivery */
    snprintf(testcase_file, sizeof(testcase_file),
             "%s/testcase_file",  output_dir.c_str());
    testcase_fd = open(testcase_file, O_RDWR | O_CREAT | O_TRUNC, 0600);
    sut_test_write = testcase_fd;
    sut_test_read = sut_test_write;
    sut_use_stdin = true;
    for(auto& s: sut_argv) {
        if (s == "@@") {
            sut_use_stdin = false;
            LOG_INFO << "AFL Exec configured to use file SUT input ("
                     << testcase_file << ")";
        }
    }

    /* Configure stdout/err debug logs */
    std::string stdout_file = "stdout";
    std::string stderr_file = "stderr";
    // TODO: Configure to redirect to VMF Logger
    if (config.getBoolParam(getModuleName(), "debugLog", DEFAULT_DEBUG)) {
        if (config.isParam(getModuleName(), "stdout"))
            stdout_file = config.getStringParam(getModuleName(), "stdout");
        std::string outfile_path = output_dir + "/" + stdout_file;
        sut_stdout = fileno(fopen(outfile_path.c_str(), "a"));

        if (config.isParam(getModuleName(), "stderr"))
            stderr_file = config.getStringParam(getModuleName(), "stderr");
        std::string errfile_path = output_dir + "/" + stderr_file;
        sut_stderr = fileno(fopen(errfile_path.c_str(), "a"));
    } else {
        sut_stdout = open("/dev/null", O_RDWR);
        sut_stderr = open("/dev/null", O_RDWR);
    }

    /* Configure manual SUT timeout */  
    if(config.isParam(getModuleName(),"timeoutInMs")) {
        use_manual_timeout = true;
        manual_timeout_ms = config.getIntParam(getModuleName(),"timeoutInMs");
    } else {
        use_manual_timeout = false;
        /* Set a default timeout value in case we can't calibrate */
        setTimeouts(DEFAULT_TIMEOUT_MS);
    }
    /* Configure SUT memory limit */
    sut_mem_limit = config.getIntParam(getModuleName(), "memoryLimitInMB", DEFAULT_SUT_MB_LIMIT);
    /* Configure Coverage bitmap size. 0 means not configured which gets autodetected later. */
    map_size = 0;
    if (config.isParam(getModuleName(), "mapSize")) {
        map_size = config.getIntParam(getModuleName(), "mapSize");
    }
    /* Configure maximum number of calibration cases */
    max_calib = config.getIntParam(getModuleName(), "maxCalibrationCases", DEFAULT_MAX_CALIB);
    /* Configure amount of trace data (both settings must be turned off to not write trace data at all)*/
    always_write_trace = config.getBoolParam(getModuleName(), "alwaysWriteTraceBits", DEFAULT_ALWAYS_TRACE);
    coverage_only_trace = config.getBoolParam(getModuleName(), "traceBitsOnNewCoverage", DEFAULT_COVERAGE_ONLY_TRACE);
    /* Write stats for code coverage data to metadata (for use by output modules) */
    write_stats = config.getBoolParam(getModuleName(), "writeStats", DEFAULT_WRITE_STATS);    
    /* Configure custom error code for crashing SUT */
    if (config.isParam(getModuleName(), "customExitCode")) {
        use_custom_exitcode = true;
        custom_exitcode = config.getIntParam(getModuleName(), "customExitCode");
    } else {
        use_custom_exitcode = false;
        custom_exitcode = 0;
    }

    /* Configure CmpLog */
    cmp_log_enabled = config.getBoolParam(getModuleName(), "cmpLogEnabled", false);
    /* Configure SUT sanitizer instrumentation */
    use_asan = config.getBoolParam(getModuleName(), "useASAN", DEFAULT_USE_ASAN);
    use_lsan = config.getBoolParam(getModuleName(), "useLSAN", DEFAULT_USE_LSAN);
    use_msan = config.getBoolParam(getModuleName(), "useMSAN", DEFAULT_USE_MSAN);
    use_ubsan = config.getBoolParam(getModuleName(), "useUBSAN", DEFAULT_USE_UBSAN);
    /* Default SUT memory limit to unlimited if configured to use ASAN */
    if (use_asan && !config.isParam(getModuleName(), "memoryLimitInMB"))
      sut_mem_limit = 0;

}

bool AFLForkserverExecutor::startForkserver() {
    if (!initFuzzerSUTIO()) {
        LOG_ERROR << "Failed to initialize Fuzzer/SUT IO: " << strerror(errno);
        return false;
    }

    if (!initCoverageMaps()) {
        LOG_ERROR << "Failed to create Fuzzer/SUT shared memory region: " << strerror(errno);
        return false;
    }
    /* Fork */
    int child_pid = fork();

    /* Check for fork failure */
    if (child_pid < 0) return false;

    /* Forkserver/SUT (Child process)
     * Spawn SUT instrumented with forkserver shim */
    if (child_pid == 0) {
        launchSUT();
        /* don't expect a return */
        return false;
    }

    /* Fuzzer (Parent process) */
    forkserver_pid = child_pid;
    initFuzzerIO();
    /* Verify that we can communicate with the SUT's shim */
    if (checkSUT() != AFL_STATUS_OK) return false;

    LOG_DEBUG << "Launched " << getModuleName() << " forkserver with pid [" << forkserver_pid << "]";

    return true;
}

bool AFLForkserverExecutor::initCoverageMaps(void) {
    /* Create a shared-memory region */
    shm_id = shmget(IPC_PRIVATE, map_size, IPC_CREAT | IPC_EXCL | 0600);
    if (shm_id < 0) return false;
    /* Attach our coverage map to the shared memory region */
    trace_bits = static_cast<uint8_t*>(shmat(shm_id, NULL, 0));
    if (trace_bits == reinterpret_cast<void*>(-1)) return false;

    virgin_trace = new uint8_t[map_size];
    virgin_hang = new uint8_t[map_size];
    virgin_crash = new uint8_t[map_size];

    old_trace = virgin_trace;
  
    memset(virgin_trace, PORCELAIN, map_size);
    memset(virgin_hang, PORCELAIN, map_size);
    memset(virgin_crash, PORCELAIN, map_size);

    /* CmpLog */
    if (cmp_log_enabled)
    {
        /* Create and attach shared region for cmplog maps */
        cmplog_shm_id = shmget(IPC_PRIVATE, sizeof(struct cmp_map), IPC_CREAT | IPC_EXCL | 0600);
        if (cmplog_shm_id < 0) return false;
        cmplog_bits = static_cast<uint8_t*>(shmat(cmplog_shm_id, NULL, 0));
        if (cmplog_bits == reinterpret_cast<void*>(-1)) return false;
    }

    return true;
}

int AFLForkserverExecutor::checkSUT(void) {
    int status;
    int read_length = readStatus(&status, 0); 

    /* Expecting a 4-byte "hello" message the first time we read from
       the status pipe. We don't care about the actual status message */
    if (read_length == 4)
        return AFL_STATUS_OK; 

    /* Otherwise, figure out what went wrong */
    /* Check for timeout */
    if (sut_hung)
        return AFL_STATUS_ERROR;

    /* Log Error number for a failed pipe read */
    if (read_length == -1) {
        LOG_ERROR << "Reading SUT status pipe failed with errno: " << strerror(errno);
    }
    /* Ask OS for Forkserver/SUT process status */
    if (waitpid(forkserver_pid, &status, 0) <= 0) {
        LOG_ERROR << "Unknown Error while retrieving forkserver status via waitpid";
        return AFL_STATUS_ERROR;
    }

    /* Check if Exec failed in the forkserver process, and we received
       the unique fail pattern via coverage map */
    if (reinterpret_cast<uint32_t*>(trace_bits)[0] == EXEC_FAIL) {
        int exec_errno = reinterpret_cast<uint32_t*>(trace_bits)[1];
        LOG_ERROR << "Forkserver failed during exec";
        LOG_ERROR << "exec failed with errno (" << exec_errno << "): " << strerror(exec_errno);
        if (exec_errno == ENOENT) {
            LOG_ERROR << "Perhaps you have the wrong SUT path:"
                      << "SUT Path: " << sut_argv[0];
        }
        return AFL_STATUS_ERROR;
    }

    /* Interpret OS-supplied status for forkserver process */
    if (WIFSIGNALED(status) != 0) {
        LOG_ERROR << "Forkserver process crashed during startup with signal number: " << WTERMSIG(status);
        return AFL_STATUS_ERROR;
    }
    
    /* Couldn't diagnose failing forkserver startup */
    LOG_ERROR << "Unknown Error while retrieving forkserver status via waitpid";
    return AFL_STATUS_ERROR;
}

int AFLForkserverExecutor::readStatus(int* result, int timeout_ms) {
    int read_length = 0;
    static struct timeval tv;
    static fd_set readfds;
    int interrupted = false;
    /* Caller doesn't want a timer.
       They mustn't afraid of this read hanging */
    if (timeout_ms == 0) 
        return read(STAT_PIPE_RD, result, 4);

    /* Set a timer in case the read hangs */
    tv.tv_sec = (timeout_ms / 1000);
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    /* Retry if we get interrupted */
    do {
        /* Wait for status pipe to be ready and detect child closing the pipe */
        FD_ZERO(&readfds);
        FD_SET(STAT_PIPE_RD, &readfds);
        int r = select(STAT_PIPE_RD+1, &readfds, NULL, NULL, &tv);
        if (r < 0) {
            if (errno == EINTR) {
                interrupted = true;
                continue;
            } else {
                return -1;
            }
        } else if (r == 0) { /* select system call timed out */
            sut_hung = 1;
            return -1;
        } else { /* r > 0, Status pipe is ready */
            /* Only retry the read (not select) if it we got this far */
            do {
                /* Attempt to read 4 bytes from the status pipe */
                read_length = read(STAT_PIPE_RD, (uint8_t *)result, 4);
                if ((read_length == -1) && (errno == EINTR))
                    interrupted = true;
                else
                    interrupted = false;
            } while (interrupted);
        }
    } while (interrupted);
    /* Return length of data read. Let the caller handle cases where we
       read more/less than 4 bytes */
    return read_length;
}

bool AFLForkserverExecutor::initFuzzerSUTIO() {
    int status[2];
    int control[2];

    /* Create status and control pipes */
    if ((pipe(status) != 0) || (pipe(control) != 0)) return false;

    /* Duplicate the pipes to known descriptor values */
    if (dup2(control[READ_PIPE], CTRL_PIPE_RD) < 0) return false;
    if (dup2(status[WRITE_PIPE], STAT_PIPE_WR) < 0) return false;

    /* No need to duplicate these descriptors since they'll remain in
       the fuzzer process */
    CTRL_PIPE_WR = control[WRITE_PIPE];
    STAT_PIPE_RD = status[READ_PIPE];

    /* Close duplicated and now uneccessary descriptors */
    close(control[READ_PIPE]);
    close(status[WRITE_PIPE]);

    return true;
}

void AFLForkserverExecutor::initFuzzerIO() {
    /* Close unecessary file descriptors */
    close(CTRL_PIPE_RD);
    close(STAT_PIPE_WR);
}

bool AFLForkserverExecutor::launchSUT() {
    initSUT();

    /* Set up exec args */
    std::vector<char *> argvp;
    for (auto &s : sut_argv) {
        if (s == "@@") 
            argvp.push_back(testcase_file);
        else
            argvp.push_back(&s[0]);
    }
    argvp.push_back(NULL);

    /* Exec SUT */
    int ret = execv(argvp[0], &argvp[0]);
    /* Report exec failure if execution reaches this code */
    reinterpret_cast<uint32_t*>(trace_bits)[0] = EXEC_FAIL;
    reinterpret_cast<uint32_t*>(trace_bits)[1] = errno;

    /* Quit forked SUT process */
    exit(ret);

    /* Why do I let the compiler boss me around? */
    return false; 
}

void AFLForkserverExecutor::initSUT() {
    if (!initSUTIO())
        throw RuntimeException("Failed to Initialize SUT IO",
                               RuntimeException::UNEXPECTED_ERROR);
    setResourceLimits();
    initSUTEnv();
}

/**
 * @brief Helper method to set the address sanitizer options
 * 
 * @param options 
 */
void AFLForkserverExecutor::getASANOptions(std::string& options) {
    options =
        ":detect_odr_violation=0"
        ":abort_on_error=1"
        ":symbolize=0"
        ":allocator_may_return_null=1"
        ":handle_segv=0"
        ":handle_sigbus=0"
        ":handle_abort=0"
        ":handle_sigfpe=0"
        ":handle_sigill=0"
        ":detect_leaks=0"
        ":malloc_context_size=0";
}

/**
 * @brief Helper method to set the leak sanitizer options
 * 
 * @param options 
 */
void AFLForkserverExecutor::getLSANOptions(std::string& options) {
    int detect_leaks;
    if (use_lsan) detect_leaks = true;
    else detect_leaks = false;

    options =
        ":detect_odr_violation=0"
        ":abort_on_error=1"
        ":symbolize=0"
        ":allocator_may_return_null=1"
        ":handle_segv=0"
        ":handle_sigbus=0"
        ":handle_abort=0"
        ":handle_sigfpe=0"
        ":handle_sigill=0"
        ":detect_leaks=" + std::to_string(detect_leaks) +
        ":exit_code=" + std::to_string(LSAN_ERROR) +
        ":fast_unwind_on_malloc=0"
        ":print_suppressions=0"
        ":malloc_context_size=30";
}

/**
 * @brief Helper method to set the memory sanitizer options
 * 
 * @param options 
 */
void AFLForkserverExecutor::getMSANOptions(std::string& options) {
    options =
        ":detect_odr_violation=0"
        ":abort_on_error=1"
        ":symbolize=0"
        ":allocator_may_return_null=1"
        ":handle_segv=0"
        ":handle_sigbus=0"
        ":handle_abort=0"
        ":handle_sigfpe=0"
        ":handle_sigill=0"
        ":detect_leaks=0"
        ":exit_code=" + std::to_string(MSAN_ERROR) +
        ":msan_track_origins=0"
        ":malloc_context_size=0";
}
/**
 * @brief Helper method to set the undefined behavior sanitizer options
 * 
 * @param options 
 */
void AFLForkserverExecutor::getUBSANOptions(std::string& options) {
    options =
        ":detect_odr_violation=0"
        ":abort_on_error=1"
        ":symbolize=0"
        ":allocator_may_return_null=1"
        ":handle_segv=0"
        ":handle_sigbus=0"
        ":handle_abort=0"
        ":handle_sigfpe=0"
        ":handle_sigill=0"
        ":detect_leaks=0"
        ":malloc_context_size=0";
}

/**
 * @brief Helper method to set the sanitizer options
 * 
 */
void AFLForkserverExecutor::initSANEnv() {
    std::string options;

    getASANOptions(options);
    setenv("ASAN_OPTIONS", options.c_str(), OVERWRITE);
    if (use_asan) setenv("AFL_USE_ASAN", "1", OVERWRITE);
    getLSANOptions(options);
    setenv("LSAN_OPTIONS", options.c_str(), OVERWRITE);
    if (use_lsan) setenv("AFL_USE_LSAN", "1", OVERWRITE);
    getMSANOptions(options);
    setenv("MSAN_OPTIONS", options.c_str(), OVERWRITE);
    if (use_msan) setenv("AFL_USE_MSAN", "1", OVERWRITE);
    getUBSANOptions(options);
    setenv("UBSAN_OPTIONS", options.c_str(), OVERWRITE);
    if (use_ubsan) setenv("AFL_USE_UBSAN", "1", OVERWRITE);
}

/**
 * @brief Helper method to initialize the SUT environment
 * 
 */
void AFLForkserverExecutor::initSUTEnv() {
    char tmp_str[1024];

    /* Isolate process to a new session */
    setsid();

    /* Prevent the linker from doing work post-fork */
    setenv("LD_BIND_NOW", "1", OVERWRITE);

    /* Set environment variables for SUT shared memory ID */
    sprintf(tmp_str, "%d", shm_id);
    setenv("__AFL_SHM_ID", tmp_str, OVERWRITE);
    sprintf(tmp_str, "%d", map_size);
    setenv("AFL_MAP_SIZE", tmp_str, OVERWRITE);
    /* CmpLog */
    if (cmp_log_enabled) {
        sprintf(tmp_str, "%d", cmplog_shm_id);
        setenv("__AFL_CMPLOG_SHM_ID", tmp_str, OVERWRITE);
    }

    /* Set sanitizer options */
    initSANEnv();
}

bool AFLForkserverExecutor::initSUTIO() {
    /* Redirect the saved file-descriptors to the SUT's stdin/out/err */
    if (sut_use_stdin) {
        if (dup2(sut_test_read, fileno(stdin)) < 0)
            return false;
    } else {
        if (dup2(open("/dev/null", O_RDWR), fileno(stdin)))
            return false;
    }

    if (dup2(sut_stdout, fileno(stdout)) < 0) return false;
    if (dup2(sut_stderr, fileno(stderr)) < 0) return false;

    /* Disable buffering to stdin/out */
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    /* Close unecessary file descriptors */
    close(sut_test_read);
    close(sut_stdout);
    close(sut_stderr);
    close(CTRL_PIPE_WR);
    close(STAT_PIPE_RD);

    return true;
}

void AFLForkserverExecutor::setResourceLimits(void) {
    struct rlimit r;

    /* File Descriptor Limit */
    /* Ensure that the SUT is allowed to have file descriptors with
     * values as high as our default constants for pipes */
    long unsigned max_fd = std::max({CTRL_PIPE_RD, CTRL_PIPE_WR, STAT_PIPE_RD, STAT_PIPE_WR});
    getrlimit(RLIMIT_NOFILE, &r);
    if (r.rlim_cur < max_fd + 1) {
        r.rlim_cur = max_fd + 2;
        setrlimit(RLIMIT_NOFILE, &r);
    }

    /* Memory Limit */
    if (sut_mem_limit > 0) {
        r.rlim_max = ((rlim_t)sut_mem_limit) << 20;
        r.rlim_cur = r.rlim_max;
        /* Some operating systems don't support RLIMIT_AS (virtual memory limit)
         * Use RLIMIT_DATA (data segment limit) in those cases */
#ifdef RLIMIT_AS 
        setrlimit(RLIMIT_AS, &r);
#else
        setrlimit(RLIMIT_DATA, &r);
#endif
    }

    /* Core dump limit */
    r.rlim_max = 0;
    r.rlim_cur = 0;
    setrlimit(RLIMIT_CORE, &r);

    /* Ignore errors, no return value */
}


int AFLForkserverExecutor::getSUTMapSize(void) {

    /* Enable AFL_DEBUG */
    setenv("AFL_DEBUG", "1", 1);

    /* Construct run command. We must redirect stderr to stdout so popen captures it,
       because AFL_DEBUG info is sent on stderr. We add a timeout to kill any waiting for stdin.*/
    char cmd[sut_argv[0].length() + 32];
    sprintf(cmd, "timeout 1s %s 2>&1", sut_argv[0].c_str());

    /* Run SUT with popen. We don't need to run it properly with args etc.
       As long as it reaches main that is enough to get info we need. That makes
       this part simple, we can ignore stdin vs file input, args,... */
    std::array<char, 4096> buffer;
    auto pipe = popen(cmd, "r");
    if (!pipe) throw std::runtime_error("popen() failed!");

    /* Parse results */
    int found_map_size = 0;
    while (!feof(pipe)) {
        if (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {

            std::string line = buffer.data();

            /* Search for "__afl_final_loc" */
            int index = line.find("__afl_final_loc");

            /* We must handle two types of lines that contain map size information:
               "Done __sanitizer_cov_trace_pc_guard_init: __afl_final_loc = 14447"
               "DEBUG: (1) id_str <null>, __afl_area_ptr 0x7f0e2018, ... , __afl_final_loc 14448,
            */

            if (index != -1)
            {
                /* Begin searching for map size at character following the magic string */
                auto it = line.begin() + index + strlen("__afl_final_loc");
                std::string nextNum = "";
                for (; it != line.end(); it++)
                {
                    char c = *it;
                    /* Skip over spaces and '=' to handle the two line types */
                    if (c == ' ' || c == '=')
                        continue;

                    /* If it's a digit, add to string. Otherwise exit */
                    if (isdigit(c))
                    {
                        nextNum += c;
                    } else {
                        break;
                    }
                }

                /* Take highest value we find */
                int extracted_map_size = atoi(nextNum.c_str());
		/* Round up to nearest 64 bytes like AFL does */
		if (extracted_map_size % 64)
		    extracted_map_size = (((extracted_map_size + 63) >> 6) << 6);
		/* Record highest size we find, output sometimes has multiple sizes */
                if (extracted_map_size > found_map_size)
                    found_map_size = extracted_map_size;
            }
        }
    }

    /* Clean up */
    pclose(pipe);
    unsetenv("AFL_DEBUG");
    
    // 0 means we didn't find a size
    return found_map_size;
}

void AFLForkserverExecutor::runCalibrationCases(StorageModule& storage, std::unique_ptr<Iterator>& iterator) {
    StorageEntry& metadata = storage.getMetadata();
    metadata.setValue(map_size_key, map_size);
    /* Remove existing timeouts to prep for calibration */
    setTimeouts(DEFAULT_TIMEOUT_MS);

    while(iterator->hasNext()) {
        StorageEntry* entry = iterator->getNext();
        /* Fetch fuzzer-generated input bytes and size from entry */
        int size = entry->getBufferSize(test_case_key);
        uint8_t* buffer = reinterpret_cast<uint8_t*>(entry->getBufferPointer(test_case_key));

        /* Dispatch test to forkserver */
        runOnForkserver(buffer, size);

        /* Calibration test cases shouldn't crash */
        if (AFL_STATUS_ERROR == sut_status)
        {
            throw RuntimeException("An initial testcase failed encountered and error while calibrating. "
                                   "Make sure that VMF can run the target.", RuntimeException::UNEXPECTED_ERROR);

        }
        else if (AFL_STATUS_CRASHED == sut_status)
        {
            LOG_WARNING << "An initial test case crashed during calibration -- ignoring test case #" << entry->getID();
            continue;
        }
        else if (AFL_STATUS_HUNG == sut_status)
        {
            LOG_WARNING << "An initial test case hung during calibration -- ignoring test case #" << entry->getID();
            continue;
        }
        //else the status is AFL_STATUS_OK

        /* Verify that we're collecting coverage */
        int found_bytes = cov_util.countBytes(trace_bits, map_size);
        if (found_bytes == 0)
            throw RuntimeException("No coverage data was received from running "
                                   "the target, but it did not crash. "
                                   "This likely means it is not instrumented.",
                                   RuntimeException::UNEXPECTED_ERROR);
                                   
        /* Record number of calibration tests */
        num_calib++;

        /* Tracking maximum and total time taken */
        if (time_taken > max_time)
            max_time = time_taken;
        sum_time += time_taken;

        LOG_INFO << "Testcase " << num_calib << ", uid = " << entry->getID() << ", size = " << size
                 << ", found bytes: " << found_bytes
                 << ", time taken: " << time_taken << " us";

        if (num_calib >= max_calib)
            break;
    }

    /* Use calibration metrics to decide on timeout values */
    calibrateTimeout(max_time, sum_time);
    /* Register our calculated timeout */
    metadata.setValue(calib_timeout_key, timeout_dur);
}

void AFLForkserverExecutor::calibrateTimeout(unsigned max_time, unsigned sum_time) {
    int timeout;

    if (num_calib > 0) {
        /* Calculate the average execution time of the calibration tests */
        int avg_time = sum_time / num_calib;

        /* Determine timeout based on calibration metrics */
        timeout = calculateTimeout(avg_time, max_time, sum_time);
        if (timeout == TIMEOUT_LOWER_BOUND) {
           LOG_WARNING << "Lower-bound timeout reached during calibration.";
        } else if (timeout == TIMEOUT_UPPER_BOUND) {
            LOG_WARNING << "Upper-bound timeout reached during calibration.";
        }

        LOG_INFO << "Calibration Metrics: "
                 << "Average (" << avg_time << " us), "
                 << "Max (" << max_time << " us)";
    }

    if (use_manual_timeout) {
        LOG_WARNING << "Using manual timeout of " << manual_timeout_ms << " ms";
        timeout = manual_timeout_ms;
    }

    if ((num_calib == 0) && !use_manual_timeout) {
        /* Use the default timeout value if we didn't run any calibration tests */
        timeout = DEFAULT_TIMEOUT_MS;
        LOG_WARNING << "Using a UNCALIBRATED default timeout.";
    }

    /* Update the executor's internal timeout values */
    setTimeouts(timeout);
    /* Remember that we're calibrated */
    calibrated = true;

    LOG_INFO << "Using a first-attempt timeout of " << timeout_short << " ms";
    LOG_INFO << "Using a second-attempt timeout of " << timeout_long << " ms";
}

int AFLForkserverExecutor::calculateTimeout(unsigned avg_time, unsigned max_time, unsigned sum_time) {
    int timeout;

    /* Pick a reasonable timeout value depending on average threshold values */
    if (avg_time > 50000) timeout = avg_time * 2;
    else if (avg_time > 10000) timeout = avg_time * 3;
    else timeout = avg_time * 5;

    /* Convert microseconds to milliseconds */
    timeout /= 1000;

    /* Round up to nearest 20 milliseconds */
    timeout = (timeout + 20) / 20 * 20;

    /* Enforce a minimum timeout of 20ms to prevent false timeouts from system jitter */
    if (timeout < TIMEOUT_LOWER_BOUND)
        timeout = TIMEOUT_LOWER_BOUND;
    /* Enforce a maximum timeout, but warn the user */
    if (timeout > TIMEOUT_UPPER_BOUND)
        timeout = TIMEOUT_UPPER_BOUND;

    return timeout;
}

int AFLForkserverExecutor::calculateLongTimeout(int timeout) {
    return (timeout * 2) + 100;
}

void AFLForkserverExecutor::setTimeouts(int timeout) {
    /* Set the provided timeout to be our default */
    timeout_dur = timeout;
    /* Set the first (shorter) of two timeouts */
    timeout_short = timeout_dur;
    /* Store a longer timeout for when the SUT hangs on its first try */
    timeout_long = calculateLongTimeout(timeout_short);

    LOG_DEBUG << "Setting timeouts to: (" << timeout_dur
              << "/" << timeout_short << "/" << timeout_long << ")";
}

void AFLForkserverExecutor::killSUT(void) {
    if (sut_pid > 0) {
        kill(sut_pid, SIGKILL);
        sut_pid = -1;
    }
    /* Then hear from the forkserver */
    if (readStatus(&sut_exitcode, NOBLOCK_LONG_TIMEOUT) != 4)
      throw RuntimeException("Failed to get SUT exit code from forkserver"
                             "after killing the hung SUT",
                             RuntimeException::UNEXPECTED_ERROR);

}

void AFLForkserverExecutor::registerStorageNeeds(StorageRegistry& registry) {
    test_case_key = registry.registerKey("TEST_CASE", StorageRegistry::BUFFER, StorageRegistry::READ_ONLY);
    exec_time_key = registry.registerKey("EXEC_TIME_US", StorageRegistry::INT, StorageRegistry::WRITE_ONLY);
    exec_status_key = registry.registerKey("AFL_EXEC_STATUS", StorageRegistry::INT, StorageRegistry::WRITE_ONLY);
    if(always_write_trace || coverage_only_trace)
    {
        //If either of these is set, trace bits will be written
        trace_bits_key = registry.registerKey("AFL_TRACE_BITS", StorageRegistry::BUFFER, StorageRegistry::WRITE_ONLY);
    }
    crashed_tag = registry.registerTag("CRASHED", StorageRegistry::WRITE_ONLY);
    hung_tag = registry.registerTag("HUNG", StorageRegistry::WRITE_ONLY);
    normal_tag = registry.registerTag("RAN_SUCCESSFULLY", StorageRegistry::WRITE_ONLY);
    has_new_coverage_tag = registry.registerTag("HAS_NEW_COVERAGE", StorageRegistry::WRITE_ONLY);
    coverage_count_key = registry.registerKey("COVERAGE_COUNT", StorageRegistry::INT, StorageRegistry::WRITE_ONLY);
    if(cmp_log_enabled)
    {
        //The additional cmp log data is only written if cmplog mode is enabled
        cmpLogMapKey = registry.registerKey("CMPLOG_MAP_BITS", StorageRegistry::BUFFER, StorageRegistry::WRITE_ONLY);
    }
}
void AFLForkserverExecutor::registerMetadataNeeds(StorageRegistry& registry) {
    cumulative_coverage_metadata = registry.registerKey("TOTAL_BYTES_COVERED", StorageRegistry::INT, StorageRegistry::WRITE_ONLY);
    map_size_key = registry.registerKey("MAP_SIZE", StorageRegistry::INT, StorageRegistry::WRITE_ONLY);
    calib_timeout_key = registry.registerKey("CALIBRATED_TIMEOUT", StorageRegistry::INT, StorageRegistry::READ_WRITE);
}
