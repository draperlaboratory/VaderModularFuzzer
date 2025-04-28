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
 * ===========================================================================*/#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#if defined(G_OS_WIN32) || defined(_WIN32)
# include <windows.h>
#else
# include <unistd.h>
#endif
#include <signal.h>

#if defined (_M_IX86)  
#pragma comment(linker, "/alternatename:_LLVMFuzzerTestOneInput=_EmptyLLVMFuzzerInitialize")
#pragma comment(linker, "/alternatename:_LLVMFuzzerInitialize=_EmptyLLVMFuzzerInitialize")
#elif defined (_M_IA64) || defined (_M_AMD64)
#pragma comment(linker, "/alternatename:LLVMFuzzerTestOneInput=EmptyLLVMFuzzerTestOneInput")
#pragma comment(linker, "/alternatename:LLVMFuzzerInitialize=EmptyLLVMFuzzerTestOneInput")
#else  /* defined (_M_IA64) || defined (_M_AMD64) */   
#error Unsupported platform   
#endif  /* defined (_M_IA64) || defined (_M_AMD64) */  

#include "vmfFrida_rt.h"

/**
 * @brief Provide empty LLVMFuzzerInitialize 
 * 
 * @param argc count (by ref)
 * @param argv char *[] (by ref) 
 * @return technically 0 is the only return value defined, in 
 * some instances non-zero is interpreted as a rejected test case
 */
int EmptyLLVMFuzzerInitialize(int *argc, char ***argv ) {
  return 0;
}

/**
 * @brief An empty LLVMFuzzerTestOneInput 
 * 
 * @param data test case data
 * @param size test case size 
 * @return technically 0 is the only return value defined
 */
int EmptyLLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  return 0;
}

/**
 * @brief Provide empty LLVMFuzzerInitialize 
 * 
 * @param argc count (by ref)
 * @param argv char *[] (by ref) 
 * 
*/
void vmfFrida_enterRT( int *argc, char ***argv ) {
  /* Ensure that any foreign CRT w.r.t RT DLL get's the crash handler installed */
  signal(SIGABRT, vmfFrida_crashNow);
  signal(SIGINT, vmfFrida_crashNow);
  signal(SIGFPE, vmfFrida_crashNow);
  signal(SIGILL, vmfFrida_crashNow);
  signal(SIGSEGV, vmfFrida_crashNow);

  /* Invoke any user supplied init */
  LLVMFuzzerInitialize( argc, argv );

  /* Call into the actual RT DLL */
  vmfFrida_runDriver( argc, argv, LLVMFuzzerTestOneInput ); 
}

int WinMain(
 HINSTANCE hInstance,
 HINSTANCE hPrevInstance,
 LPSTR     lpCmdLine, /* Not used, as direction is to GetCommandLineW */
 int       nShowCmd
) {
  int argc;
  LPWSTR *_argv;
  char **argv;
  _argv = CommandLineToArgvW( GetCommandLineW(), &argc );
  argv = malloc( sizeof(char *) * argc );
  /* Check for NULL TBD */
  for( int i = 0; i < argc; i++ ) {
    int len;
    len = WideCharToMultiByte(CP_ACP,
                              0,
                              _argv[i],
                              -1,
                              NULL,
                              0, NULL, NULL);
    argv[i] = malloc(len+1);
    WideCharToMultiByte(CP_ACP,
                          0,
                          _argv[i],
                          -1,
                          argv[i],
                          len, NULL, NULL);
  }
  vmfFrida_enterRT( &argc, &argv );
}

int main( int argc, char**argv ) {
  vmfFrida_enterRT( &argc, &argv );
}