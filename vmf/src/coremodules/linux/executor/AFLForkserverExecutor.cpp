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
#include "AFLForkserverExecutor.hpp"
#include "Logging.hpp"
#include "VaderUtil.hpp"
#include <unistd.h>
#include <filesystem>

using namespace vader;
using namespace aflpp;

#include "ModuleFactory.hpp"
REGISTER_MODULE(AFLForkserverExecutor);

/**
 * @brief Builder method to support the ModuleFactory
 * Constructs an instance of this class
 * @return Module* 
 */
Module* AFLForkserverExecutor::build(std::string name)
{
    return new AFLForkserverExecutor(name);
}

/**
 * @brief Initialization method
 * This involves setting up AFLPlusPlus's forkserver with default values
 * as well as any non-default values from Vader's config
 * 
 * @param config 
 */
void AFLForkserverExecutor::init(ConfigInterface& config)
{
    std::string outFileDir = config.getOutputDir() + "/tmp";
    VaderUtil::createDirectory(outFileDir.c_str());
    snprintf(tmpOutFile, sizeof(tmpOutFile), "%s/in_file_%d",  outFileDir.c_str(), ::getpid());

    //Check for a limit on calibration cases
    //Set this parameter to -1 to disable the feature
    maxCalibrationCases = config.getIntParam(getModuleName(), "maxCalibrationCases", 300);

    //Check for a manually specified timeout value
    useManualTimeout = false;
    if(config.isParam(getModuleName(),"timeoutInMs"))
    {
        useManualTimeout = true;
        manualTimeoutMs = config.getIntParam(getModuleName(),"timeoutInMs");
    }

    map_size = get_map_size();
    afl_state_init(&afl_state, map_size);
    init_count_class16();
    afl_fsrv_init(&afl_state.fsrv);
    std::vector<std::string> sut_argv = config.getStringVectorParam(getModuleName(),"sutArgv");

    //Check that the SUT is present
    const std::filesystem::path sut_path = std::filesystem::u8path(sut_argv[0]);
    bool exists = std::filesystem::exists(sut_path);
    if(!exists)
    {
        LOG_ERROR << "The specified SUT was not found at this location: " << sut_argv[0];
        throw RuntimeException("SUT not found", RuntimeException::CONFIGURATION_ERROR);
    }

    LOG_INFO << "AFL Exec configured to run SUT: " << sut_argv[0];
    std::vector<char*> cstrings;
    cstrings.reserve(sut_argv.size() + 1);
    for(auto& s: sut_argv) {
        if (s == "@@") {
            afl_state.fsrv.use_stdin = false;
            LOG_INFO << "AFL Exec configured to use file input";
            cstrings.push_back(tmpOutFile);
        } else {
            cstrings.push_back(&s[0]);
        }
    }
    cstrings.push_back(NULL); // argv[-1] must be NULL
    if (afl_state.fsrv.use_stdin) {
        LOG_INFO << "AFL Exec configured to use stdin input";
    }
    afl_state.afl_env.afl_debug_child = 0; // Suppress SUT stdout
    afl_state.fsrv.target_path = (u8*) &sut_argv[0][0];
    afl_state.fsrv.trace_bits = afl_shm_init(&shm, afl_state.fsrv.map_size, false);
    int memoryLimit = config.getIntParam(getModuleName(), "memoryLimitInMB", 128);
    afl_state.fsrv.mem_limit = memoryLimit;
    memset(afl_state.virgin_bits, 255, map_size);
    memset(afl_state.virgin_tmout, 255, map_size);
    memset(afl_state.virgin_crash, 255, map_size);
    afl_state.fsrv.out_file = (u8*) tmpOutFile;
    afl_state.fsrv.out_fd = open((const char*)afl_state.fsrv.out_file, O_RDWR | O_CREAT | O_TRUNC, DEFAULT_PERMISSION);
    if (afl_state.fsrv.out_fd == -1) {
      throw RuntimeException(("Unable to create file " + std::string(tmpOutFile) + ": " +
			      strerror(errno) + ", errno=" + std::to_string(errno)).c_str(),
			     RuntimeException::UNEXPECTED_ERROR);
    }
    afl_state.fsrv.dev_null_fd = open("/dev/null", O_RDWR);
    fsrv_signal_stop = 0;
    afl_fsrv_start(&afl_state.fsrv, cstrings.data(), &fsrv_signal_stop, afl_state.afl_env.afl_debug_child);

    //default values (prior to first exectution)
    old_bits = afl_state.virgin_bits;
    timeTaken = 0;
    returnStatus = AFL_STATUS_ERROR;
    maxTime = 0;
    sumTime = 0;
    numCalibrationTestCases = 0;
}

/**
 * @brief Construct a new AFLForkserverExecutor::AFLForkserverExecutor object
 *
 * @param name
 */
AFLForkserverExecutor::AFLForkserverExecutor(std::string name) :
    AFLExecutor(name)
{

}

/**
 * @brief Destroy the AFLForkserverExecutor::AFLForkserverExecutor object
 *
 */
AFLForkserverExecutor::~AFLForkserverExecutor()
{
    fsrv_signal_stop = 1;
    afl_fsrv_deinit(&afl_state.fsrv);
    afl_shm_deinit(&shm);

    std::remove(tmpOutFile);
}


void AFLForkserverExecutor::runTestCase(char* buffer, int size)
{
    size_t aflsize = (size_t) size;
    u8* aflbuffer = (u8*) buffer;
    afl_fsrv_write_to_testcase(&afl_state.fsrv, aflbuffer, aflsize);
    u64 startTime = get_cur_time_us();
    fsrv_run_result_t res = afl_fsrv_run_target(&afl_state.fsrv, afl_state.fsrv.exec_tmout, &fsrv_signal_stop);
    u64 endTime = get_cur_time_us();
    timeTaken = (int)(endTime - startTime);

    // If the testcase hung, we rerun it with hang_tmout instead of exec_tmout to confirm the hang
    if (FSRV_RUN_TMOUT == res)
    {
      startTime = get_cur_time_us();
      res = afl_fsrv_run_target(&afl_state.fsrv, afl_state.hang_tmout, &fsrv_signal_stop);
      endTime = get_cur_time_us();
      timeTaken = (int)(endTime - startTime);
    }

    //evaluate run results and set old_bits pointer
    old_bits = afl_state.virgin_bits;
    if(FSRV_RUN_OK == res)
    {
        returnStatus = AFL_STATUS_OK;
    }
    else if (FSRV_RUN_TMOUT == res)
    {
        returnStatus = AFL_STATUS_HUNG;
        old_bits = afl_state.virgin_tmout;
    }
    else if (FSRV_RUN_CRASH == res)
    {
        returnStatus = AFL_STATUS_CRASHED;
        old_bits = afl_state.virgin_crash;
    }
    else
    {
        //FSRV_RUN_ERROR or FSRV_RUN_NOINST or FSRV_RUN_NOBITS
        //Of these, only FSRV_RUN_ERROR should occur outside of a dry run
        LOG_ERROR << "FSRV_RUN_ERROR or FSRV_RUN_NOINST or FSRV_RUN_NOBITS";
        throw RuntimeException("Forkserver run error",
                                RuntimeException::UNEXPECTED_ERROR);

    }
}

void AFLForkserverExecutor::runCalibrationCase(char* buffer, int size)
{
    //First check to see if we've done enough calibration, if there is a limit
    if(maxCalibrationCases > 0)
    {
        if(numCalibrationTestCases >= maxCalibrationCases)
        {
            return; //Stop running calibration, we have enough data
        }
    }

    numCalibrationTestCases++;
    runTestCase(buffer, size);

    LOG_INFO << "Testcase " << numCalibrationTestCases << ", size= " << size << ", time taken: " << timeTaken << " us";

    // Check for crashes. Initial testcases shouldn't crash. If they do user should be prompted to debug.
    if (AFL_STATUS_ERROR == returnStatus)
        throw RuntimeException("An initial testcase crashed while calibrating. "
                    "Remove crashing testcases from the intial set, and make sure that "
                    "VMF can run the target.", RuntimeException::UNEXPECTED_ERROR);

    // Make sure that we are properly getting coverage data back from the target
    if (0 == getCoverageByteCount())
        throw RuntimeException("No coverage data was received from running the target, but it did not crash." 
                "This likely means it is not instrumented.", RuntimeException::UNEXPECTED_ERROR);

    // Track maximum and average time
    if (timeTaken > maxTime)
    {
        maxTime = timeTaken;
    }
    sumTime += timeTaken;
}

void AFLForkserverExecutor::completeCalibration()
{
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

  
    /* Pick a reasonable timeout value. VMF uses the same heuristic as AFL++:
    Set timeout to 5x the average or the maximum for a single test, whichever is larger.
    A smaller multiplier is used if the target it slow. */

    int avgTime = sumTime / numCalibrationTestCases; // Times are measured in usec
    int timeout;
    if (avgTime > 50000)
    timeout = avgTime * 2;
    else if (avgTime > 10000)
    timeout = avgTime * 3;
    else
    timeout = avgTime * 5;

    // Convert microseconds to milliseconds
    timeout /= 1000;

    // Round up to nearest 20 milliseconds
    timeout = (timeout + 20) / 20 * 20;

    // Bound timeout to [20, 1000] ms. Less than 20ms can lead to false hangs from system jitter.
    if (timeout < 20)
        timeout = 20;
    if (timeout > 1000)
        timeout = 1000;
    if(!useManualTimeout)
    {
        LOG_INFO << "Average time: " << avgTime << " us";
        LOG_INFO << "Max time: " << maxTime << " us";
        LOG_INFO << "Using a timeout of " << timeout << " ms";
    }
    else
    {
        LOG_WARNING << "Using manual timeout of " << manualTimeoutMs << " ms (instead of computed timeout " << timeout << " ms)";
        timeout = manualTimeoutMs;
    }

    afl_state.fsrv.exec_tmout = timeout;

    // The hang timeout is a longer, more generous value than exec timemout to confirm hangs.
    afl_state.hang_tmout = timeout * 2 + 100;
}

// Classified counts are binned into groups based on hitcount and should be used when comparing coverage
char* AFLForkserverExecutor::getCoverageBitsClassified()
{
    classify_counts(&afl_state.fsrv);
    return (char*)afl_state.fsrv.trace_bits;  
}

char* AFLForkserverExecutor::getCoverageBits()
{
    return (char*)afl_state.fsrv.trace_bits;
}

int AFLForkserverExecutor::getCoverageSize()
{
    return map_size;
}

int AFLForkserverExecutor::getExecutionTime()
{
    return timeTaken;
}

int AFLForkserverExecutor::getReturnStatus()
{
    return returnStatus;
}

int AFLForkserverExecutor::getCoverageByteCount()
{
    return count_bytes(&afl_state, afl_state.fsrv.trace_bits);
}

int AFLForkserverExecutor::getCorpusCoverageByteCount()
{
    return count_non_255_bytes(&afl_state, afl_state.virgin_bits);
}

bool AFLForkserverExecutor::hasNewCoverageBits()
{
    bool hasNewBits = has_new_bits_unclassified(&afl_state, old_bits);
    return hasNewBits;
}
