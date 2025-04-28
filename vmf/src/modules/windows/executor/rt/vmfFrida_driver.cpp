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
 * ===========================================================================*/#include <stdlib.h>
#include <string>
#include <sstream>
#include <ios>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <stdarg.h>
#include <varargs.h>
#include <signal.h>

#include "configService.hpp"
#include "getopt.h"

#define min min
#include <windows.h>
#include <psapi.h>

#include "vmfFrida_instrumenter.hpp"

static std::set<std::string> _instrumentDLLs;

#define DEFINE_DLL
#include "vmfFrida_rt.h"

#include "vmfFrida_rtimpl.hpp"

namespace fs = std::filesystem;
using namespace vmfFrida_rt;

#undef __declspec /* Intellisense getting confused from _mingw.h somehow. */

typedef int (*test_entry)(const uint8_t *data, size_t len);
static test_entry _testFunction;

ConfigService theConfiguration;
static int _timeout;
static std::string _myId;

static BOOL _inFuzzer = false;

static HMODULE _hSUT = (HMODULE) INVALID_HANDLE_VALUE;

/* Fuzzer use state */
static HANDLE _hPipe;
static HANDLE _hMapFile;
static HANDLE _hTestFile;

static LPVOID _testDataShared;
static size_t _testDataMax;

/* Standalone state */
std::vector<std::string> _testData;
std::vector<std::string>::iterator _curTest;

/* RunDriver state */
static size_t _map_size;
static bool _debug_log = false;
static bool _disable_instrumentation = false;

enum class LogVerbosity { Debug, Warning, Error };

/** @brief Super cheap and low-dependency logging
 * If error we also put message to stderr 
 */
void Log( const LogVerbosity level, const char *fmt, ... ) {
    va_list args;
    va_start(args, fmt);
    int len = _vscprintf( fmt, args ) + 1; 
    char *buffer = (char *)alloca( len );
    vsprintf_s(buffer, len, fmt, args );
    OutputDebugString( buffer );
    if ( LogVerbosity::Error == level  ) {
        fputs(buffer, stderr );
    }
    va_end(args);
}
#define log_debug( fmt, ... ) do { if (_debug_log) Log( LogVerbosity::Debug, fmt, __VA_ARGS__ ); } while(0)
#define log_warning( fmt, ... ) do { Log( LogVerbosity::Warning, fmt, __VA_ARGS__ ); } while(0)
#define log_error_fatal( fmt, ... ) do { Log( LogVerbosity::Error, fmt, __VA_ARGS__ ); vmfFrida_exit(__LINE__); } while(0)

static uint8_t *_trace_bits; 
static uint64_t _prev_pc = 0;

static std::string _mapPattern;
static bool _mapCollectMeta;
static size_t _numTests;
static size_t _nTest;
static LPVOID _activeTest;
static size_t _activeLength;

void vmfFrida_exit( int cause ) {
    log_debug( "Closing SUT for cause from line %d", cause );
    if ( _hPipe != INVALID_HANDLE_VALUE ) 
        CloseHandle( _hPipe );
    exit(cause);
}

void fuzzer_state_init(void ) {
    /* Set up Names for connections to controller */
    std::ostringstream stringStream;
    stringStream << "\\\\.\\pipe\\" << _myId;
    std::string pipeName = stringStream.str();

    stringStream.str("");
    stringStream << "Local\\traceBitsFor" << _myId;
    std::string traceBitsName = stringStream.str();

    stringStream.str("");
    stringStream << "Local\\testDataFor" << _myId;
    std::string testName = stringStream.str();

    /* Since we are launched by the server, we should not encounter a case where the pipe is not there 
       and we need to WaitNamedPipe before we can CreateFile to get our connection.
       If the pipe is not there, like we got launched manually, then abort is fine */

    _hPipe = CreateFile(
        pipeName.c_str(),
        GENERIC_READ|GENERIC_WRITE, // only need read access
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
        );

    if (_hPipe == INVALID_HANDLE_VALUE) {
        log_error_fatal( "Cannot get pipe GLE=%x", GetLastError());
    }

    _hTestFile = CreateFileMapping(
                    INVALID_HANDLE_VALUE,    // use paging file
                    NULL,                    // default security
                    PAGE_READWRITE,          // read/write access
                    0,                       // maximum object size (high-order DWORD)
                    (DWORD)_testDataMax,                // maximum object size (low-order DWORD)
                    testName.c_str());                 // name of mapping object

    if (_hTestFile == NULL)
    {
        log_error_fatal( "Cannot get test file GLE=%x", GetLastError());
    }
    _testDataShared = (MapViewOfFile(_hTestFile,   // handle to map object
                            FILE_MAP_ALL_ACCESS, // read/write permission
                            0,
                            0,
                            _testDataMax));

    if (_testDataShared == NULL)
    {
        log_error_fatal( "Cannot get test data ptr GLE=%x", GetLastError());
    }

    _hMapFile = CreateFileMapping(
                    INVALID_HANDLE_VALUE,    // use paging file
                    NULL,                    // default security
                    PAGE_READWRITE,          // read/write access
                    0,                       // maximum object size (high-order DWORD)
                    (DWORD)_map_size,                // maximum object size (low-order DWORD)
                    traceBitsName.c_str());                 // name of mapping object

    if (_hMapFile == NULL)
    {
        log_error_fatal( "Cannot get test map file GLE=%x", GetLastError());
    }
    _trace_bits = static_cast<uint8_t*>(MapViewOfFile(_hMapFile,   // handle to map object
                            FILE_MAP_ALL_ACCESS, // read/write permission
                            0,
                            0,
                            _map_size));

    if (_trace_bits == NULL)
    {
        log_error_fatal( "Cannot get test map ptr GLE=%x", GetLastError());
    }

    DWORD numBytes = 0;
    DWORD readySignal[4];
    readySignal[0] = FRIDA_RT_READY;
    readySignal[1] = *reinterpret_cast<uint32_t*>(_trace_bits);
    readySignal[2] = *static_cast<uint32_t*>(_testDataShared);
    readySignal[3] = FRIDA_RT_VERSION;

    BOOL result = WriteFile(
        _hPipe,
        readySignal, // the data from the pipe will be put here
        sizeof(readySignal), // number of bytes allocated
        &numBytes, // this will store number of bytes actually read
        NULL // not using overlapped IO
        );
    if ( !result || numBytes != sizeof(readySignal)) {
        log_error_fatal( "Cannot get write pipe GLE=%x", GetLastError());
    }
    log_debug("We have signaled ready\n", 0);  // see MSVC __VA_OPT__ c++20 issues.
    _inFuzzer = true;
}

bool vmfFrida_test_next() {
    if ( _inFuzzer ) {
        DWORD numBytes;
        DWORD readySignal[3];

        if ( _numTests-- == 0 ) {
            log_debug( "Test limit done", 0); // see MSVC __VA_OPT__ c++20 issues.
            return false;
        }
        BOOL result = ReadFile(
            _hPipe,
            readySignal, // the data from the pipe will be put here
            sizeof(readySignal), // number of bytes allocated
            &numBytes, // this will store number of bytes actually read
            NULL // not using overlapped IO
            );
        if ( !result || numBytes != sizeof(readySignal)) {
            log_error_fatal("Reading go signal GLE=%x", GetLastError());
        }
        if ( readySignal[0] != FRIDA_RT_GO ) {
            log_warning("On test %x %d %d", readySignal[0], readySignal[1], readySignal[2]);
            log_error_fatal("Message sequence error with RT");
        }
        _nTest = readySignal[1];
        _activeTest = (char *)_testDataShared + sizeof(uint32_t);
        if ( *(uint32_t *)_testDataShared != readySignal[2] ) {
            log_warning("On test %x %d %d", readySignal[0], readySignal[1], readySignal[2]);
            log_error_fatal("Error with mismatch between self attributed length %x and control channel length %d", *(uint32_t *)_testDataShared, readySignal[2]);
        }
        _activeLength = readySignal[2];
    } else {
        if ( _curTest == _testData.end() ) {
            return false;
        }
        auto index = _curTest - _testData.begin();
        _nTest = index;
        _activeTest = (LPVOID)_curTest->data();
        _activeLength = _curTest->length();
    }
    return true;
}

void vmfFrida_test_done( int status, DWORD timeoutUS = 0 ) {
    if ( !_mapPattern.empty() ) {
        const int nameLen = MAX_PATH;
        char *buf = (char *)alloca(nameLen);
        std::snprintf(buf, nameLen, "%s.map%04d",_mapPattern.c_str(),
                (int)_nTest);
        std::ofstream mapFile(buf);
        mapFile.write((const char *)_trace_bits, _map_size);
    }
    if ( _inFuzzer ) {
        DWORD resultSignal[4];
        BOOL result;
        DWORD numBytes;

        /* Tag the last test remaining with the COFFEE (As in sut-runtime needs refill!) */
        resultSignal[0] = _numTests == 0? FRIDA_RT_DONE: FRIDA_RT_NEXT;
        resultSignal[1] = (DWORD)_nTest;
        resultSignal[2] = (DWORD)status; /* Result code */
        resultSignal[3] = timeoutUS;
        result = WriteFile(
            _hPipe,
            resultSignal, // the data from the pipe will be put here
            sizeof(resultSignal), // number of bytes allocated
            &numBytes, // this will store number of bytes actually read
            NULL // not using overlapped IO
            );
        if ( !result || numBytes != sizeof(resultSignal)) {
            log_error_fatal( "writing done signal GLE=%x", GetLastError());
        }
        log_debug("--- TEST %lld len %lld %d:%u us", _numTests, _activeLength, status, timeoutUS );
    } else {
        printf("---- TEST %lld len %lld = %d:%u us\n", _nTest, _activeLength, status, timeoutUS );
        _curTest++;
    }
    _prev_pc = 0;
}

BOOL WINAPI _CtrlHandler(DWORD dwCtrlType) {
  switch (dwCtrlType) {
    case CTRL_C_EVENT:
      vmfFrida_test_done( FRIDA_STATUS_CRASHED );
      vmfFrida_exit(__LINE__);
      break;
    case CTRL_BREAK_EVENT:
      vmfFrida_test_done( FRIDA_STATUS_CRASHED );
      vmfFrida_exit(__LINE__);
      break;
  }
  return FALSE;
}

static void _CrashHandler(int code) { 
    log_debug(" Signal exit %d", code);
    vmfFrida_test_done( FRIDA_STATUS_CRASHED ); 
    vmfFrida_exit(__LINE__);
}

static LONG CALLBACK _SEHandler(PEXCEPTION_POINTERS ExceptionInfo) {
  switch (ExceptionInfo->ExceptionRecord->ExceptionCode) {
    case EXCEPTION_ACCESS_VIOLATION:
    case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
    case EXCEPTION_STACK_OVERFLOW:
      vmfFrida_test_done( FRIDA_STATUS_CRASHED );
      vmfFrida_exit(__LINE__);
      break;
    case EXCEPTION_DATATYPE_MISALIGNMENT:
    case EXCEPTION_IN_PAGE_ERROR:
      vmfFrida_test_done( FRIDA_STATUS_ERROR );
      vmfFrida_exit(__LINE__);
      break;
    case EXCEPTION_ILLEGAL_INSTRUCTION:
    case EXCEPTION_PRIV_INSTRUCTION:
      vmfFrida_test_done( FRIDA_STATUS_ERROR );
      vmfFrida_exit(__LINE__);
      break;
    case EXCEPTION_FLT_DENORMAL_OPERAND:
    case EXCEPTION_FLT_DIVIDE_BY_ZERO:
    case EXCEPTION_FLT_INEXACT_RESULT:
    case EXCEPTION_FLT_INVALID_OPERATION:
    case EXCEPTION_FLT_OVERFLOW:
    case EXCEPTION_FLT_STACK_CHECK:
    case EXCEPTION_FLT_UNDERFLOW:
    case EXCEPTION_INT_DIVIDE_BY_ZERO:
    case EXCEPTION_INT_OVERFLOW:
      vmfFrida_test_done( FRIDA_STATUS_ERROR );
      vmfFrida_exit(__LINE__);
      break;
    // This is an undocumented exception code corresponding to a Visual C++
    // Exception.
    //
    // See: https://devblogs.microsoft.com/oldnewthing/20100730-00/?p=13273
    case 0xE06D7363:
      vmfFrida_test_done( FRIDA_STATUS_ERROR );
      vmfFrida_exit(__LINE__);
      break;
      // TODO: Handle (Options.HandleXfsz)
  }
  return EXCEPTION_CONTINUE_SEARCH;
}

int vmfFrida_initDriver( int argc, char **argv, int (*entry)(const unsigned char *data, size_t len) )
{
    bool standalone = false;
    bool inFuzzer = false;
    std::string configContext = "FridaExecutor";

    // Parse argc/argv
    for (;;) {
        switch (getopt(argc, argv, "y:t:C:c:I:i:d:s:")) {
            case 's':  // Save map w/ pattern
                _mapPattern = optarg;
                _mapCollectMeta = true;
                continue;
           case 'i': {  // Input (multiple supported)
                if ( inFuzzer ) {
                    log_error_fatal("Cannot be given an ID and explicit input");
                }
                standalone = true;
                std::ifstream infile(optarg, std::ios::binary);
                if (infile.fail()) {
                    return false;
                }
                _testData.emplace_back(std::istreambuf_iterator<char>(infile),
                                      std::istreambuf_iterator<char>());
                continue;
            }                
            case 'd': {  // Directory input
                if ( inFuzzer ) {
                    log_error_fatal("Cannot be given an ID and explicit input");
                }
                standalone = true;
                for (const auto &entry : fs::directory_iterator(optarg)) {
                    std::ifstream infile(entry.path(), std::ios::binary);
                    if (infile.fail()) {
                        return false;
                    }
                    _testData.emplace_back(
                        std::istreambuf_iterator<char>(infile),
                        std::istreambuf_iterator<char>());
                }
                continue;
            }
            case 't':  // Timeout
                _timeout = std::stoi(optarg);
                continue;
            case 'C': 
                configContext = optarg;
                continue;
            case 'c':  // Config (multiple supported)
                theConfiguration.addSource(optarg);
                continue;
            case 'y':  // Literal Config
                theConfiguration.addSource(optarg, strlen(optarg));
                continue;
            case 'I':
                if ( standalone ) {
                    log_error_fatal("Cannot be given an ID and explicit input");
                }
                inFuzzer = true;
                _myId = optarg;
                continue;
        }
        break;
    }

    _disable_instrumentation = theConfiguration.resolve( configContext.c_str(), "disableInstrumentation", false );

    _debug_log = theConfiguration.resolve( configContext.c_str(), "debugLog", false );

    /* Map size is currently fixed at 64K, this is coupled to the instrumentation assembly and does not support a variable size */
    _map_size = 65536; 

    _testDataMax = theConfiguration.resolve( configContext.c_str(), "maxTestSize", static_cast<size_t>(1024*1024) ); 
    _numTests = theConfiguration.resolve( configContext.c_str(), "numTestsPerProcess", static_cast<size_t>(1000*1000) ); 

    std::vector<std::string> DLLNames = theConfiguration.resolve( configContext.c_str(), "instrument", std::vector<std::string>() );
    _instrumentDLLs = std::set<std::string>( DLLNames.begin(), DLLNames.end() );

    std::string dll = theConfiguration.resolve( configContext.c_str(), "sutDLL", std::string() ); 
    std::string fncName = theConfiguration.resolve( configContext.c_str(), "testEntry", std::string("LLVMFuzzerTestOneInput") ); 
    std::string initName = theConfiguration.resolve( configContext.c_str(), "testInit", std::string("LLVMFuzzerInitialize") ); 
    if ( !dll.empty() ) {
        fs::path dllPath( dll );
        _hSUT = LoadLibrary(dll.c_str());
        _instrumentDLLs.insert( fs::path( dll ).filename().string() );
        entry = (int (*)(const unsigned char *data, size_t len)) GetProcAddress( _hSUT, fncName.c_str() );
        auto init = (int (*)(int *argc, char *(*argv)[1])) GetProcAddress( _hSUT, initName.c_str() );
        if ( init ) 
        {
            int fakeArgc = 1;
            char* fakeArgv[1];
                
            /* Some harness have been seen to pass fuzzing arguments. We do not provide LLVM LibFuzzer compatibile arguments, 
            So if we see the harness telling us there are more than 1 (program name) then let's signal a failure. */
            (*init)( &fakeArgc, &fakeArgv );
            if ( fakeArgc > 1 ) {
                /* Let's be about as noisy as we can on this condition */
                fprintf(stderr, "Cannot handle libFuzzer command line input from harness\n");            
                OutputDebugString( "Cannot handle libFuzzer command line input from harness\n" );
                log_error_fatal( "Cannot handle libFuzzer command line input from harness\n");
            }
        }
    }

    if ( inFuzzer ) {
        fuzzer_state_init();
    } else if ( standalone ) {
        _trace_bits = new uint8_t[_map_size];
        memset( _trace_bits, 0, _map_size);
        _curTest = _testData.begin();

    } else {
        log_error_fatal("Input must be given explicitly (with -i or -d) or a fuzzer must be given (-I)");
    }
    _testFunction = entry;

    return TRUE;
}

FRT_PUBLIC void vmfFrida_crashNow( int cause )
{
    _CrashHandler(cause);
}

FRT_PUBLIC void vmfFrida_runDriver( int *argc, char ***argv, int (*entry)(const uint8_t *data, size_t len) ) 
{
    /* Need to initialize our argv */
    vmfFrida_initDriver( *argc, *argv, entry );

    /* Now we can create the instrumentation */
    VMFFridaInstrumenter instrumenter( _trace_bits, &_prev_pc, &_nTest, _instrumentDLLs, _debug_log );

    log_debug("Instance allowed %d tests", _numTests );

    SetUnhandledExceptionFilter(_SEHandler);

    // These are supposed to be global data
    if ( signal(SIGABRT, _CrashHandler) == SIG_ERR ) {
        log_error_fatal( "Cannot establish signal handler ");
    }
    if ( signal(SIGINT, _CrashHandler) == SIG_ERR ) {
        log_error_fatal( "Cannot establish signal handler ");
    }
    // These are supposed to be thread local
    if ( signal(SIGFPE, _CrashHandler) == SIG_ERR ) {
        log_error_fatal( "Cannot establish signal handler ");
    }
    if ( signal(SIGILL, _CrashHandler) == SIG_ERR ) {
        log_error_fatal( "Cannot establish signal handler ");
    }
    if ( signal(SIGSEGV, _CrashHandler) == SIG_ERR ) {
        log_error_fatal( "Cannot establish signal handler ");
    }
    SetConsoleCtrlHandler(_CtrlHandler, TRUE);

    
    if ( !_disable_instrumentation ) {
        instrumenter.Enable();
    }

    /* Signal is 0xDECAFBAD, testNo, testSize */
    while( vmfFrida_test_next() ) {
        log_debug("+++ TEST %lld len %lld", _numTests, _activeLength );
        using std::chrono::high_resolution_clock;
        using std::chrono::duration_cast;
        using std::chrono::duration;
        using std::chrono::microseconds;

        auto t1 = high_resolution_clock::now();

        if ( !_disable_instrumentation ) {
            instrumenter.Activate( _testFunction ); 
        }
        _testFunction( (const uint8_t *)_activeTest, _activeLength);
        if ( !_disable_instrumentation ) {
            instrumenter.Deactivate();
        }
        auto t2 = high_resolution_clock::now();
        const duration<double, std::micro> us = t2 - t1;

        vmfFrida_test_done( FRIDA_STATUS_OK, (DWORD)us.count() );
    }
    if ( !_mapPattern.empty() ) {
        bool first = true;
        const int nameLen = MAX_PATH;
        char *buf = (char *)alloca(nameLen);
    
        std::snprintf(buf, nameLen, "%s.mapmeta.json",_mapPattern.c_str() );
        std::ofstream mapMetaFile(buf);      

        instrumenter.DumpMeta( mapMetaFile ); 
        mapMetaFile.close();
    }
    return;
}

