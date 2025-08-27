/* =============================================================================
 * Vader Modular Fuzzer (VMF)
 * Portions copyright (c) 2021-2025 The Charles Stark Draper Laboratory, Inc.
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
 VMFDriver.c - an interface between VMF and libFuzzer-style harnesses
 
 Modified from https://github.com/AFLplusplus/AFLplusplus/blob/stable/utils/aflpp_driver/aflpp_driver.c
 AFL++ is maintained by:
    Marc "van Hauser" Heuse mh@mh-sec.de
    Dominik Maier mail@dmnk.co
    Andrea Fioraldi andreafioraldi@gmail.com
    Heiko "hexcoder-" Eissfeldt heiko.eissfeldt@hexco.de
    frida_mode is maintained by @Worksbutnottested
 Originally developed by Michal "lcamtuf" Zalewski.

 This file allows VMF to fuzz libFuzzer-style target functions
 (LLVMFuzzerTestOneInput) with VMF using AFL++-style persistent in-memory fuzzing

*/

#ifdef __cplusplus
extern "C" {
#endif

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>

// Defines taken from /vmf/src/modules/linux/executor/AFLForkserverExecutor.hpp
#define MAX_TC_LEN (1024000)  // Matches SHARED_MEM_MAX_SIZE

// Defines copied from AFLplusplus/include/types.h
#if __GNUC__ < 6
  #ifndef likely
    #define likely(_x) (_x)
  #endif
  #ifndef unlikely
    #define unlikely(_x) (_x)
  #endif
#else
  #ifndef likely
    #define likely(_x) __builtin_expect(!!(_x), 1)
  #endif
  #ifndef unlikely
    #define unlikely(_x) __builtin_expect(!!(_x), 0)
  #endif
#endif

/* Global: Number of fuzzing iterations per fork */
int g_N_iter = 10000;

#define SECTION_RODATA \
  __attribute__((used, retain)) __attribute__((section(".rodata")))

int __afl_sharedmem_fuzzing = 1;

#ifndef __AFL_FUZZ_TESTCASE_LEN
  // Define variables that are provided by AFL++ instrumentation runtime
  // when compiling with other than afl-clang-fast/afl-clang-lto
  unsigned int  *__afl_fuzz_len = 0;
  unsigned char *__afl_fuzz_ptr = 0;
  unsigned char *__afl_area_ptr = 0;
  unsigned int   __afl_map_size = 0;
  #define __afl_persistent_loop(n) ( --n > 0 )
  #define __afl_manual_init() { }

#else
  extern unsigned int  *__afl_fuzz_len;
  extern unsigned char *__afl_fuzz_ptr;
  extern unsigned char *__afl_area_ptr;
  extern unsigned int   __afl_map_size;
  int __afl_persistent_loop(unsigned int);
  void __afl_manual_init();

#endif

// libFuzzer interface is thin, so we don't include any libFuzzer headers.
/* Using the weak attributed on LLVMFuzzerTestOneInput() breaks oss-fuzz but
   on the other hand this is what Google needs to make LLVMFuzzerRunDriver()
   work. Choose your poison Google! */
/*__attribute__((weak))*/ int LLVMFuzzerTestOneInput(const uint8_t *Data,
                                                     size_t         Size);
__attribute__((weak)) int     LLVMFuzzerInitialize(int *argc, char ***argv);
__attribute__((weak)) void    LLVMFuzzerCleanup(void);
__attribute__((weak)) int     LLVMFuzzerRunDriver(
        int *argc, char ***argv, int (*callback)(const uint8_t *data, size_t size));

// Default nop ASan hooks for manual poisoning when not linking the ASan
// runtime
// https://github.com/google/sanitizers/wiki/AddressSanitizerManualPoisoning
__attribute__((weak)) void __asan_poison_memory_region(
    void const volatile *addr, size_t size) {
  (void)addr;
  (void)size;
}

__attribute__((weak)) void __asan_unpoison_memory_region(
    void const volatile *addr, size_t size) {
  (void)addr;
  (void)size;
}

__attribute__((weak)) void *__asan_region_is_poisoned(void *beg, size_t size);

// Notify fuzzer about persistent mode.
SECTION_RODATA static const char AFL_PERSISTENT[] = "##SIG_AFL_PERSISTENT##";

// Notify fuzzer about deferred forkserver.
SECTION_RODATA static const char AFL_DEFER_FORKSVR[] = "##SIG_AFL_DEFER_FORKSRV##";

// Use this optionally defined function to output sanitizer messages even if
// user asks to close stderr.
__attribute__((weak)) void __sanitizer_set_report_fd(void *);

// Keep track of where stderr content is being written to, so that
// dup_and_close_stderr can use the correct one.
static FILE *output_file;

// If the user asks us to duplicate stderr, then do it.
static void maybe_duplicate_stderr() {

  char *stderr_duplicate_filename =
      getenv("VMF_DRIVER_STDERR_DUPLICATE_FILENAME");

  if (!stderr_duplicate_filename) return;

  FILE *stderr_duplicate_stream =
      freopen(stderr_duplicate_filename, "a+", stderr);

  if (!stderr_duplicate_stream) {
    fprintf(
        stderr,
        "Failed to duplicate stderr to VMF_DRIVER_STDERR_DUPLICATE_FILENAME");
    abort();
  }

  output_file = stderr_duplicate_stream;
}

// Most of these I/O functions were inspired by/copied from libFuzzer's code.
static void discard_output(int fd) {

  FILE *temp = fopen("/dev/null", "w");
  if (!temp) abort();
  dup2(fileno(temp), fd);
  fclose(temp);
}

static void close_stdout() {
  discard_output(STDOUT_FILENO);
}

// Prevent the targeted code from writing to "stderr" but allow sanitizers and
// this driver to do so.
static void dup_and_close_stderr() {
  int output_fileno = fileno(output_file);
  int output_fd = dup(output_fileno);
  if (output_fd <= 0) abort();
  FILE *new_output_file = fdopen(output_fd, "w");
  if (!new_output_file) abort();
  if (!__sanitizer_set_report_fd) return;
  __sanitizer_set_report_fd((void *)(long int)output_fd);
  discard_output(output_fileno);
}

// Close stdout and/or stderr if user asks for it.
static void maybe_close_fd_mask() {
  char *fd_mask_str = getenv("VMF_DRIVER_CLOSE_FD_MASK");
  if (!fd_mask_str) return;
  int fd_mask = atoi(fd_mask_str);
  if (fd_mask & 2) dup_and_close_stderr();
  if (fd_mask & 1) close_stdout();
}

// Define LLVMFuzzerMutate to avoid link failures for targets that use it
// with libFuzzer's LLVMFuzzerCustomMutator.
__attribute__((weak)) size_t LLVMFuzzerMutate(uint8_t *Data, size_t Size,
                                              size_t MaxSize) {
  // LLVMFuzzerMutate should not be called from VMFDriver
  return 0;
}

// For testing purposes, execute with input from file provided as parameter
static int TestFile(char *fname,
                    int (*callback)(const uint8_t *data,
                                    size_t         size)) {

  unsigned char *buf = (unsigned char *)malloc(MAX_TC_LEN);

  __asan_poison_memory_region(buf, MAX_TC_LEN);
  ssize_t prev_length = 0;

  int fd = open(fname, O_RDONLY);
  if (-1 < fd) {
    ssize_t length = syscall(SYS_read, fd, buf, MAX_TC_LEN);

    if (length > 0) {

      if (length < prev_length) {
        __asan_poison_memory_region(buf + length, prev_length - length);
      } else {
        __asan_unpoison_memory_region(buf + prev_length, length - prev_length);
      }

      prev_length = length;

      callback(buf, length);
    }

    if (fd > 0) { close(fd); }
  }

  free(buf);
  return 0;
}

// Print out useful information about running this program
static void help(char* name) {
  fprintf(stdout, "\n"
    "Usage:  %s [-n NUM_ITER] [-f INPUT_FILE1] [-f INPUT_FILEn]\n"
    "Execute a fuzz harness designed for libFuzzer compatibility (using LLVMFuzzerTestOneInput)\n"
    "Reads test case data from fuzzer-provided shmem unless -f is specified\n"
    "\n"
    "Options:\n"
    " -f <filename>   \n"
    " -n <num_iter>   number of iterations before respawning the process\n"
    "                 default: %d\n"
    "                 also environment variable AFL_FUZZER_LOOPCOUNT\n"
    "                 NOTE: Only used with shmem-provided test cases\n"
    " -h    display this help message\n"
    "\n",

  name, g_N_iter);
}

char* optarg;

__attribute__((weak)) int main(int argc, char **argv) {

  int opt = -1;
  char* fname = 0;

  if (LLVMFuzzerInitialize) {
    LLVMFuzzerInitialize(&argc, &argv);
  }

  while (-1 != (opt = getopt(argc, argv, "f:hn:"))) {
    switch (opt) {
      case 'f':
        fname = optarg;
        TestFile(fname, LLVMFuzzerTestOneInput);
        break;

      case 'n':
        g_N_iter = atoi(optarg);
        break;

      case 'h':
      case '?':
      default:
        help(argv[0]);
        return 0;
    }
  }

  /* If -f flag was not used, expect shmem input from fuzzer */
  if (0 == fname) {
    LLVMFuzzerRunDriver(&argc, &argv, LLVMFuzzerTestOneInput);
  }
  
  return 0;
}

// Call the harness entry point using data provided over shared memory
// Also uses AFL++ deferred initialization and "persistent mode" looping
__attribute__((weak)) int LLVMFuzzerRunDriver(
    int *argcp, char ***argvp,
    int (*callback)(const uint8_t *data, size_t size)) {

  int    argc = *argcp;
  char **argv = *argvp;

  output_file = stderr;
  maybe_duplicate_stderr();
  maybe_close_fd_mask();

  if (getenv("AFL_FUZZER_LOOPCOUNT")) {
    g_N_iter = atoi(getenv("AFL_FUZZER_LOOPCOUNT"));
  }

  __afl_manual_init();

  // Confirm everything is good to go
  assert(g_N_iter > 0);
  assert(__afl_fuzz_ptr != 0);
  assert(__afl_fuzz_len != 0);

  __asan_poison_memory_region(__afl_fuzz_ptr, MAX_TC_LEN);
  size_t prev_length = 0;

  // for speed only insert asan functions if the target is linked with asan
  if (unlikely(__asan_region_is_poisoned)) {
    while (__afl_persistent_loop(g_N_iter)) {

      size_t length = *__afl_fuzz_len;

      if (likely(length)) {
        if (length < prev_length) {
          __asan_poison_memory_region(__afl_fuzz_ptr + length,
                                      prev_length - length);

        } else if (length > prev_length) {
          __asan_unpoison_memory_region(__afl_fuzz_ptr + prev_length,
                                        length - prev_length);
        }

        prev_length = length;

        callback(__afl_fuzz_ptr, length);
      }
    }

  } else {

    while (__afl_persistent_loop(g_N_iter)) {
      callback(__afl_fuzz_ptr, *__afl_fuzz_len);
    }
  }

  if (LLVMFuzzerCleanup) {
    LLVMFuzzerCleanup();
  }

  return 0;
}

#ifdef __cplusplus
}
#endif

