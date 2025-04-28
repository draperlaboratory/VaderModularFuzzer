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
#include <string>
#include <filesystem> 

#include "AFLFeedback.hpp"
#include "FridaExecutor.hpp"
#include "Logging.hpp"
#include "ModuleFactory.hpp"
#include "VmfUtil.hpp"
#include "VmfRand.hpp"

#include "rt/vmfFrida_rtimpl.hpp"

using namespace vmfFrida_rt;
using namespace vmf;
REGISTER_MODULE(FridaExecutor);

#include <windows.h>
#include <stdio.h>
#include <limits>

size_t FridaExecutor::_instanceCounter;

/**
 * @brief Builder method
 * 
 * @param name the module name
 * @return Module* the newly constructed module instance
 */
Module *FridaExecutor::build(std::string name) {
    return new FridaExecutor(name);
}

void FridaExecutor::releaseResources() {
  if ( _sut_stderr_file != NULL ) {
    fclose( _sut_stderr_file );
    _sut_stderr_file = NULL;
  }
  if ( _sut_stdout_file != NULL ) {
    fclose( _sut_stdout_file );
    _sut_stdout_file = NULL;
  }
  /* Kill all processes in that group */
  TerminateProcess( _pi.hProcess, 100 );
  WaitForSingleObject( _pi.hProcess, timeout_dur );
  /* Kill the forkserver */

  UnmapViewOfFile(trace_bits);
  CloseHandle(_hMapFile);    

  delete[] virgin_trace;
  delete[] virgin_hang;
  delete[] virgin_crash;
}

/**
 * @brief Construct a new FridaExecutor object
 * 
 * @param name the module name
 */
FridaExecutor::FridaExecutor(std::string name) :
    ExecutorModule(name), cov_util(), 
        _instanceId( std::to_string( GetCurrentProcessId()) + '_' + std::to_string(++_instanceCounter)) {
    _nProcessesStarted = 0;
}

FridaExecutor::~FridaExecutor() {
    releaseResources();
}

void FridaExecutor::init(ConfigInterface& config) {
    _processFlags = 0;
    _nTest = 0;
    _nTimeoutRaw = 0;

    loadConfig(config);
    initSharedMemory();
    initSUTControl();
    
    if (!startSUT()) {
        LOG_ERROR << "Failed to launch SUT";
        throw RuntimeException("Failed to launch SUT", RuntimeException::UNEXPECTED_ERROR);
    }
}

void FridaExecutor::runCalibrationCases(StorageModule& storage, std::unique_ptr<Iterator>& iterator) {
    /* void - no calibration behavior */
}

void FridaExecutor::runTestCase(StorageModule& storage, StorageEntry* entry) {
    /* Fetch fuzzer-generated input bytes and size from entry */
    uint32_t size = entry->getBufferSize(test_case_key);
    uint8_t* buffer = reinterpret_cast<uint8_t*>(entry->getBufferPointer(test_case_key));

    if ( size == (uint32_t)-1 ) {
        throw RuntimeException("test case has unallocated buffer", RuntimeException::UNEXPECTED_ERROR);
    }
    /* Run the test */
    execTestCase(buffer, size);

    /* Record execution stats */
    handleStatus(storage, entry);
}

void FridaExecutor::execTestCase(uint8_t *buffer, uint32_t size) {
    /* Retry if the SUT hangs */ 
    /* Reset SUT hung status flag */

    /* Clear previous run's coverage trace */
    memset(trace_bits, 0, map_size);

    *static_cast<uint32_t *>(_testDataShared) = size;
    memcpy( static_cast<uint8_t *>(_testDataShared) + sizeof(uint32_t), buffer, size );

    /* Identify SUT execution status */
    waitForResultsThenReady(size);
}

void FridaExecutor::waitForResultsThenReady( uint32_t size ) {
    DWORD numBytes = 0;
	DWORD goSignal[4];
	DWORD readySignal[4];
    BOOL result;
    const int goSize = sizeof(DWORD) * 3;
    const int doneSize = sizeof(DWORD) * 4;
    int nRetry = 0;

	goSignal[0] = FRIDA_RT_GO;
    goSignal[1] = (DWORD)++_nTest; // Allowing truncation, used for ensuring consistency of sequence
    goSignal[2] = size; 
    do {
        /* If we do not have a SUT alive (either by retry or previous test abandoned), start one and try. */
        if ( nRetry > 0 || !_sut_presumed_alive ) {
            startSUT(); // We don't care if this instance failed as we are in a retry loop
            // Reset the size in the indicated buffer (since the startSUT verification overwrites) 
            *static_cast<uint32_t *>(_testDataShared) = size;
        }
        readySignal[2] = FRIDA_STATUS_UNKNOWN;
        numBytes = 0;
        LOG_DEBUG << " nTest " << _nTest << " size " << size;
        result = TransactNamedPipe( _hPipe, 
            goSignal,
            goSize, 
            readySignal,
            doneSize,
            &numBytes,
            &_overlapped );
        if (!result) { /* Results are not ready */
            if ( GetLastError() == ERROR_IO_PENDING) { // Waiting?
                DWORD dwWaitResult = WaitForSingleObject(_overlapped.hEvent, timeout_dur);
                if (dwWaitResult == WAIT_OBJECT_0) {
                    if ( GetOverlappedResult(_hPipe, &_overlapped, &numBytes, FALSE) != 0) {
                        if ( numBytes == 16 ) {
                            break; 
                        } else {
                            LOG_WARNING << "Unexpected read length";
                        }
                    } 
                    LOG_WARNING << "Unclean SUT termination, presuming crash GLE=" << GetLastError();
                    readySignal[2] = FRIDA_STATUS_CRASHED;
                    readySignal[3] = -1;
                    numBytes = doneSize;
                    break;
                } else if ( dwWaitResult == WAIT_TIMEOUT ) {
                    _nTimeoutRaw++;
                    LOG_WARNING << "Raw timeout count " << _nTimeoutRaw << " with duration " << timeout_dur;
                    readySignal[2] = FRIDA_STATUS_HUNG;
                    readySignal[3] = -1;
                    numBytes = doneSize;
                    CancelIoEx(_hPipe, &_overlapped);
                    TerminateProcess( _pi.hProcess, 100 ); // Force it to die, 
                    break; 
                } else {
                    LOG_WARNING << "Failure on wait GLE=" << GetLastError();
                    // Fall through to retry test case 
                }
            }
        } else {
            if ( numBytes == 16 ) {
                break; // Done with retry got result
            } else {
                LOG_INFO << "Result without data "; 
                // Fall through to retry test case 
            }
        }
    } while (++nRetry < _start_retry);
    if (nRetry >= _start_retry) {
        throw RuntimeException("Cannot establish SUT running");
    }
    sut_status = readySignal[2];
    /* Anyway we made it out, we should presume that on these conditions, the SUT is gone. */
    if ( readySignal[0] == 0xC0FFEE || sut_status == FRIDA_STATUS_CRASHED || sut_status == FRIDA_STATUS_HUNG ) {
        DisconnectNamedPipe(_hPipe);
        _sut_presumed_alive = false;
        // Mark this test as being abandoned and presumed complete, so ensure the next restarts sut.
    }
    return;
}

void FridaExecutor::loadConfig(ConfigInterface &config) {
    
    std::string output_dir = config.getOutputDir() + "/frida_exec";
    VmfUtil::createDirectory(output_dir.c_str());
    const int maxVar = 32767;
    char *pathVal = (char *)alloca( maxVar );
    char *newPathVal = (char *)alloca( maxVar );
    std::string binDir = VmfUtil::getExecutablePath();
    {
        DWORD len;
        if ( (len = GetEnvironmentVariable( "PATH", pathVal, 32767 )) == 0 ) {
            throw RuntimeException("Cannot get PATH value");
        }
        /* Cannot fail with size since we gave it the max */
        if ( (binDir.length() + len) > maxVar)
        {
            throw RuntimeException("combined path to long");
        }
        strcpy( newPathVal, binDir.c_str() );
        strcat( newPathVal, ";");
        strcat( newPathVal, pathVal );
        SetEnvironmentVariable( "PATH", newPathVal );
    }
    std::ostringstream stringStream;
    stringStream << "\\\\.\\pipe\\" << _instanceId;
    _pipeName = stringStream.str();

    stringStream.str("");
    stringStream << "Local\\traceBitsFor" << _instanceId;
    _traceBitsName = stringStream.str();

    stringStream.str("");
    stringStream << "Local\\testDataFor" << _instanceId;
    _testName = stringStream.str();

    /* Configure SUT arguments */
    std::vector<std::string> defaultArgv(1); 
    defaultArgv[0] = (std::filesystem::path(binDir) / std::filesystem::path("vmf_frida_rtentry.exe")).string();

    _sut_argv = config.getStringVectorParam(getModuleName(),"sutArgv", defaultArgv);

    stringStream.str("");
    auto args = _sut_argv.begin();

    std::string config_path = output_dir + "\\" + getModuleName() + "-config.yaml";
    // Could << " -y " << ;
    { 
        FILE *tempConfig; 
        std::string myConfig = config.getAllParamsYAML( getModuleName() );
        fopen_s(&tempConfig, config_path.c_str(), "w");
        fwrite( myConfig.c_str(), 1, myConfig.length(), tempConfig );
        fclose( tempConfig );
    }
    stringStream << *args++ << " -I " << _instanceId << " " << " -c " << config_path << " ";
    for (; args != _sut_argv.end(); args++ )
      stringStream << *args << " "; // TBD check for quating needs here... 
    
    _sutCommandLine = stringStream.str();

    /* Configure stdout/err debug logs */
    _processFlags = CREATE_NO_WINDOW;

    /* If debugLog is specified, default is to redirect stdoud,stderr. Otherwise, they redirection is optional, though
       always both. */
    if (config.getBoolParam(getModuleName(), "debugLog", DEFAULT_DEBUG) || 
        (config.isParam( getModuleName(), "stdout") || config.isParam( getModuleName(), "stderr")) ) {
        std::string stdout_file;
        std::string stderr_file;

        stdout_file = config.getStringParam(getModuleName(), "stdout", "stdout");
        std::string outfile_path = output_dir + "/" + stdout_file;
        _sut_stdout_file = fopen(outfile_path.c_str(), "a");

        stderr_file = config.getStringParam(getModuleName(), "stderr", "stderr");
        std::string errfile_path = output_dir + "/" + stderr_file;
        _sut_stderr_file = fopen(errfile_path.c_str(), "a");
    } else {
        _sut_stdout_file = NULL;
        _sut_stderr_file = NULL;
    }

    _start_retry = DEFAULT_START_RETRY; // No a configuration item yet. 

    /* Configure manual SUT timeout */  
    timeout_dur = config.getIntParam(getModuleName(),"timeoutInMs", DEFAULT_TIMEOUT_MS);
    
    /* Configure SUT memory limit */
    sut_mem_limit = config.getIntParam(getModuleName(), "memoryLimitInMB", DEFAULT_SUT_MB_LIMIT);

    /* Configure Coverage bitmap size */
    map_size = FRIDA_MAP_SIZE; 

    /* Configure amount of trace data (both settings must be turned off to not write trace data at all)*/
    always_write_trace = config.getBoolParam(getModuleName(), "alwaysWriteTraceBits", DEFAULT_ALWAYS_TRACE);
    coverage_only_trace = config.getBoolParam(getModuleName(), "traceBitsOnNewCoverage", DEFAULT_COVERAGE_ONLY_TRACE);
    /* Write stats for code coverage data to metadata (for use by output modules) */
    write_stats = config.getBoolParam(getModuleName(), "writeStats", DEFAULT_WRITE_STATS);    
}

bool FridaExecutor::startSUT() {
    // Create a process and associate it with the job
    STARTUPINFO si;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    memset(&_pi, 0, sizeof(_pi));

    _sut_presumed_alive = false;
// Set up members of the STARTUPINFO structure. 
// This structure specifies the STDIN and STDOUT handles for redirection.
    if ( _sut_stderr_file != NULL ) {
        si.hStdError = (HANDLE)_get_osfhandle(_fileno(_sut_stderr_file));
        si.hStdOutput = (HANDLE)_get_osfhandle(_fileno(_sut_stdout_file));
        si.dwFlags |= STARTF_USESTDHANDLES;
    }
 

    LPSTR cmdLine = _sutCommandLine.data();
    LOG_DEBUG << "Starting: " << _sutCommandLine;
    if (!CreateProcess(NULL, cmdLine, NULL, NULL, TRUE, 
            CREATE_SUSPENDED | _processFlags, NULL, NULL, &si, &_pi)) {
        printf("Error creating process: %d\n", GetLastError());
        CloseHandle(_hJob);
        return false;
    }

    // Associate the process with the job
    if (!AssignProcessToJobObject(_hJob, _pi.hProcess)) {
        printf("Error associating process with job: %d\n", GetLastError());
        CloseHandle(_hJob);
        CloseHandle(_pi.hProcess);
        CloseHandle(_pi.hThread);
        return false;
    }

    /* Provide a challenge through shared memory and expect that the client of our pipe responds with our challenge 
       This provides evidence that the client is reading the right shared memory. */
    uint32_t expectedReadySignal[4];
    uint32_t receivedReadySignal[4];
    VmfRand* rand = VmfRand::getInstance();
    expectedReadySignal[0] = FRIDA_RT_READY;
    expectedReadySignal[1] = static_cast<uint32_t>(rand->randBetween(0, std::numeric_limits<uint32_t>::max()));
    expectedReadySignal[2] = static_cast<uint32_t>(rand->randBetween(0, std::numeric_limits<uint32_t>::max()));
    expectedReadySignal[3] = FRIDA_RT_VERSION;
    *reinterpret_cast<uint32_t *>(trace_bits) = expectedReadySignal[1];
    *static_cast<uint32_t *>(_testDataShared) = expectedReadySignal[2];

    // Resume the process
    ResumeThread(_pi.hThread);
    _nProcessesStarted++;

    // This call blocks until a client process connects to the pipe 
    DWORD numBytes = 0;
    BOOL result = ConnectNamedPipe(_hPipe, &_overlapped);
    // https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-connectnamedpipe
    // it's okay to have an error return if the specific error is PIPE CONNECTED? Strange behavior win32....
    if (!result ) {
        if ( GetLastError() == ERROR_IO_PENDING) {
            DWORD dwWaitResult = WaitForSingleObject(_overlapped.hEvent, timeout_dur);
            if (dwWaitResult == WAIT_OBJECT_0) {
                result = GetOverlappedResult(_hPipe, &_overlapped, &numBytes, FALSE);
            } else {
                return false;
            }
        }
    }
    if (!result && GetLastError() != ERROR_PIPE_CONNECTED ) {
        return false;
    }

    result = ReadFile(
        _hPipe, // handle to our outbound pipe
        receivedReadySignal, // data to send
        sizeof(receivedReadySignal), // length of data to send (bytes)
        &numBytes, // will store actual amount of data sent
        NULL // not using overlapped IO
        );
    if ( !result || numBytes != sizeof(receivedReadySignal)) {
        return false;
    }
    /* Version check will eventually become non-equivalence, based on future */
    if ( expectedReadySignal[0] != receivedReadySignal[0] || 
        expectedReadySignal[1] != receivedReadySignal[1] || 
        expectedReadySignal[2] != receivedReadySignal[2] || 
        expectedReadySignal[3] != receivedReadySignal[3] ) {
        return false;
    }
    LOG_DEBUG << "Launched " << getModuleName() << " forkserver with pid [" << forkserver_pid << "]";

    // The pipe connected; change to message-read mode. 
    DWORD dwMode = PIPE_READMODE_MESSAGE; 
    result = SetNamedPipeHandleState( 
      _hPipe,    // pipe handle 
      &dwMode,  // new pipe mode 
      NULL,     // don't set maximum bytes 
      NULL);    // don't set maximum time 
    if (!result) 
    {
        LOG_ERROR << "SetNamedPipeHandleState failed. GLE=" << std::hex << GetLastError(); 
    }
    /* If we are best believe the sut is running, then note that */
    _sut_presumed_alive = true;
    /* Always start with empty trace  */
    memset(trace_bits, 0, map_size);
    return true;
}

bool FridaExecutor::initSUTControl(void) {
    const DWORD nInBufferSize = 4*sizeof(DWORD);
    const DWORD nOutBufferSize = 4*sizeof(DWORD);
    const DWORD nDefaultTimeoutMS = 1000;


    memset(&_overlapped, 0, sizeof(_overlapped));
    _overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

    _hPipe = CreateNamedPipe(_pipeName.c_str(), 
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,       // read/write access 
        PIPE_TYPE_MESSAGE |       // message type pipe 
        PIPE_READMODE_MESSAGE |   // message-read mode 
        PIPE_WAIT,                // blocking mode 
        PIPE_UNLIMITED_INSTANCES, // max. instances  
        nOutBufferSize,                  // output buffer size 
        nInBufferSize,                  // input buffer size 
        nDefaultTimeoutMS,                        // client time-out 
        NULL);                    // default security attribute     PIPE_ACCESS_DUPLEX | PIPE_TYPE_MESSAGE | PIPE_READMODE_BYTE,
    if (_hPipe == INVALID_HANDLE_VALUE) {
        LOG_ERROR << "Error creating named pipe: " << GetLastError();
        return false;
    }
    if ( ! SetHandleInformation(_hPipe, HANDLE_FLAG_INHERIT, 0) ) {
        LOG_ERROR << "Error creating named pipe: " << GetLastError();
        return false;
    }
    
    // Create a job object
    _hJob = CreateJobObject(NULL, NULL);
    if (_hJob == NULL) {
        printf("Error creating job object: %d\n", GetLastError());
        return false;
    }

    // Set the memory limit for the job
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION info;
    memset(&info, 0, sizeof(info));
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_PROCESS_MEMORY;
    info.ProcessMemoryLimit = sut_mem_limit * 1024 * 1024;
    if (!SetInformationJobObject(_hJob, JobObjectExtendedLimitInformation, &info, sizeof(info))) {
        printf("Error setting memory limit: %d\n", GetLastError());
        CloseHandle(_hJob);
        return false;
    }
    return true;
}

bool FridaExecutor::initSharedMemory(void) {
    _hTestFile = CreateFileMapping(
                    INVALID_HANDLE_VALUE,    // use paging file
                    NULL,                    // default security
                    PAGE_READWRITE,          // read/write access
                    0,                       // maximum object size (high-order DWORD)
                    _testDataMax,                // maximum object size (low-order DWORD)
                    _testName.c_str());                 // name of mapping object

    if (_hTestFile == NULL)
    {
        LOG_ERROR << "Could not create file mapping object: " << GetLastError();
        return false;
    }
    _testDataShared = (MapViewOfFile(_hTestFile,   // handle to map object
                            FILE_MAP_ALL_ACCESS, // read/write permission
                            0,
                            0,
                            _testDataMax));

    if (_testDataShared == NULL)
    {
        LOG_ERROR << "Could not map view of file: " << GetLastError();
        CloseHandle(_hTestFile);
        return false;
    }

    _hMapFile = CreateFileMapping(
                    INVALID_HANDLE_VALUE,    // use paging file
                    NULL,                    // default security
                    PAGE_READWRITE,          // read/write access
                    0,                       // maximum object size (high-order DWORD)
                    map_size,                // maximum object size (low-order DWORD)
                    _traceBitsName.c_str());                 // name of mapping object

    if (_hMapFile == NULL)
    {
        LOG_ERROR << "Could not create file mapping object: " << GetLastError();
        return false;
    }
    trace_bits = static_cast<uint8_t*>(MapViewOfFile(_hMapFile,   // handle to map object
                            FILE_MAP_ALL_ACCESS, // read/write permission
                            0,
                            0,
                            map_size));

    if (trace_bits == NULL)
    {
        LOG_ERROR << "Could not map view of file: " << GetLastError();
        CloseHandle(_hMapFile);
        return false;
    }

    virgin_trace = new uint8_t[map_size];
    virgin_hang = new uint8_t[map_size];
    virgin_crash = new uint8_t[map_size];

    old_trace = virgin_trace;
  
    memset(virgin_trace, PORCELAIN, map_size);
    memset(virgin_hang, PORCELAIN, map_size);
    memset(virgin_crash, PORCELAIN, map_size);

    return true;
}

void FridaExecutor::registerStorageNeeds(StorageRegistry& registry) {
    test_case_key = registry.registerKey("TEST_CASE", StorageRegistry::BUFFER, StorageRegistry::READ_ONLY);
    exec_time_key = registry.registerKey("EXEC_TIME_US", StorageRegistry::UINT, StorageRegistry::WRITE_ONLY);
    if(always_write_trace || coverage_only_trace)
    {
        //If either of these is set, trace bits will be written
        trace_bits_key = registry.registerKey("AFL_TRACE_BITS", StorageRegistry::BUFFER_TEMP, StorageRegistry::WRITE_ONLY);
    }
    crashed_tag = registry.registerTag("CRASHED", StorageRegistry::WRITE_ONLY);
    hung_tag = registry.registerTag("HUNG", StorageRegistry::WRITE_ONLY);
    normal_tag = registry.registerTag("RAN_SUCCESSFULLY", StorageRegistry::WRITE_ONLY);
    has_new_coverage_tag = registry.registerTag("HAS_NEW_COVERAGE", StorageRegistry::WRITE_ONLY);
    coverage_count_key = registry.registerKey("COVERAGE_COUNT", StorageRegistry::UINT, StorageRegistry::WRITE_ONLY);
}

void FridaExecutor::registerMetadataNeeds(StorageRegistry& registry) {
    cumulative_coverage_metadata = registry.registerKey("TOTAL_BYTES_COVERED", StorageRegistry::UINT, StorageRegistry::WRITE_ONLY);
}


void FridaExecutor::handleStatus(StorageModule& storage, StorageEntry *entry) {
    /* Update status-specific metadata */
    switch (sut_status) {
        case FRIDA_STATUS_HUNG:
            entry->addTag(hung_tag);
            /* Update pointer to compare hanging cumulative  coverage */ 
            old_trace = virgin_hang;
            break;
        case FRIDA_STATUS_CRASHED:
            entry->addTag(crashed_tag);
            /* Update pointer to compare crashing cumulative coverage */ 
            old_trace = virgin_crash;
            break;
        case FRIDA_STATUS_OK:
            entry->addTag(normal_tag);
            /* Update pointer to compare general cumulative coverage */ 
            old_trace = virgin_trace;
            break;
        case FRIDA_STATUS_UNKNOWN:
            LOG_ERROR << "SUT gave no response: " << sut_status; 
            break;
        case FRIDA_STATUS_ERROR:
        default:
            entry->addTag(crashed_tag);
            /* Update pointer to compare crashing cumulative coverage */ 
            old_trace = virgin_crash;
            /* Handle unexpected errors as crashes, since this afford some potential for investigating behavior. */
            LOG_ERROR << "Unexpected result: " << sut_status << " from SUT"; 
            break;
            
    }

    /* Record SUT execution time */
    entry->setValue(exec_time_key, static_cast<unsigned int>(time_taken));

    /* Check for new coverage, write new coverage tag and coverage bits to storage, as relevant*/
    handleCoverageBitmap(storage,entry);
}

void FridaExecutor::handleCoverageBitmap(StorageModule& storage, StorageEntry* entry)
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
        entry->setValue(coverage_count_key, cov_util.countBytes(trace_bits, map_size));

        /* Write classified coverage bits, if the coverage_only_trace flag was set.
         * Skip this if always_write-trace is also set, because the bits have then already been written */
        if(coverage_only_trace && !always_write_trace)
        {
            writeOrOverwriteTraceBits(storage,entry);
        }
    
        /* Calculate cumulative coverage over all test cases so far */
        if (write_stats)
        {
            unsigned int cumulative_coverage = cov_util.countNon255Bytes(virgin_trace, map_size);
            metadata.setValue(cumulative_coverage_metadata, cumulative_coverage);
        }
    }

}

void FridaExecutor::writeOrOverwriteTraceBits(StorageModule& storage, StorageEntry* entry)
{
    char* buf;
    if (entry->hasBuffer(trace_bits_key))  //allows test case to be re-run, if need be
        buf = entry->getBufferPointer(trace_bits_key);
    else
        buf = entry->allocateBuffer(trace_bits_key, map_size);

    memcpy(buf, trace_bits, map_size);
}
