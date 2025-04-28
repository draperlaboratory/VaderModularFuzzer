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
/*
 * external declarations for vmfFrida runtime library intended for use by harness.
 */
#include <stdint.h>

#ifdef __cplusplus
#define FRT_LANG "C"
#else
#define FRT_LANG 
#endif

#ifdef _WIN32
#   ifdef DEFINE_DLL
#       define FRT_PUBLIC __declspec(dllexport)
#   else 
#       define FRT_PUBLIC __declspec(dllimport)
#   endif
#else 
#   ifdef DEFINE_DLL
#       define FRT_PUBLIC __attribute__ ((visibility ("default")))
#   else 
#       define FRT_PUBLIC __attribute__ ((visibility ("hidden")))
#   endif
#endif

/** @brief Do a test with data[size] input
 * @return -1 has meaning for libFuzzer https://llvm.org/docs/LibFuzzer.html#rejecting-unwanted-inputs
 * this is currently not supported in VMF. 
 */
extern FRT_LANG int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);
extern FRT_LANG int LLVMFuzzerInitialize(int *argc, char ***argv);

/** @brief Invoke the runtime executor loop */
extern FRT_LANG FRT_PUBLIC void vmfFrida_runDriver( int *argc, char ***argvm, int (*entry)(const uint8_t *data, size_t size) );

/** @brief Cause a crash with integer cause */
extern FRT_LANG FRT_PUBLIC void vmfFrida_crashNow( int cause );

