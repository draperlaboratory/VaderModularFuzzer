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

// VMF copied and modified from AFL++

// Compare types reverse engineered from https://github.com/AFLplusplus/AFLplusplus/blob/v4.31c/instrumentation/cmplog-instructions-pass.cc#L354-L384
#define CMP_TYPE_NEQ 0
#define CMP_TYPE_EQ 1
#define CMP_TYPE_GT 2
#define CMP_TYPE_GTE 3
#define CMP_TYPE_LT 4
#define CMP_TYPE_LTE 5
// 6 and 7 unused
#define CMP_TYPE_NE_FP 8
#define CMP_TYPE_EQ_FP 9
#define CMP_TYPE_GT_FP 10
#define CMP_TYPE_GTE_FP 11
#define CMP_TYPE_LT_FP 12
#define CMP_TYPE_LTE_FP 13
// 14 and 15 unusued, 15 claimed by VMF
#define CMP_TYPE_NONE 15 // Defined by VMF to mean not set

/*
   american fuzzy lop++ - cmplog header
   ------------------------------------

   Originally written by Michal Zalewski

   Forkserver design by Jann Horn <jannhorn@googlemail.com>

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                     Heiko Eißfeldt <heiko.eissfeldt@hexco.de>,
                     Andrea Fioraldi <andreafioraldi@gmail.com>,
                     Dominik Maier <mail@dmnk.co>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2022 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   Shared code to handle the shared memory. This is used by the fuzzer
   as well the other components like afl-tmin, afl-showmap, etc...

 */

#ifndef _AFL_CMPLOG_H
#define _AFL_CMPLOG_H

#define CMP_MAP_W 65536
#define CMP_MAP_H 32
#define CMP_MAP_RTN_H (CMP_MAP_H / 2)

#define CMP_TYPE_INS 0
#define CMP_TYPE_RTN 1

/** Version information. This version of the data structure matches AFL 4.30c **/
#define CMPLOG_MAJOR_VERSION 4
#define CMPLOG_MINOR_VERSION 30

namespace vmf
{
/**
 * @brief The cmp_header is used to maintain information about the comparison data stored at that index.
 * Each header corresponds to one possible compare instruction in the program and is used to store metadata 
 * about that comparison.
 */
#pragma pack (push, 1)
struct cmp_header {
  ///Maintains the count for how many comparisons at this index were logged.
  unsigned hits : 6;
  ///Indicates the size in bytes of the comparisons stored in the log for this header. Value is size in bytes minus one.
  unsigned shape : 5;
  ///Has one of two values: either CMP_TYPE_INS  (value 0, normal comparison instructions) or CMP_TYPE_RTN (value 1, function logging).
  unsigned type : 1;
  ///Indicates the type of comparison (equal, not equal, equal or less than) that occurred
  unsigned attribute : 4;
};
#pragma pack (pop)

/**
 * @brief The cmp_operands log stores the actual runtime values used in comparisons. 
 * For each k  index into the header table, there is an array of size CMP_MAP_H of cmp_operands. 
 * 
 * The v0 and v1 fields contain the actual comparison data. For example, if 17 is compared to 18, 
 * then v0 would be 17 and v1 would be 18 in the cmp_operands  log entry. Up to CMP_MAP_H 
 * can be stored at each index, after which the log section is treated as a circular buffer
 * and the early entries become overwritten.
 *
 * The additional fields for more lhs and rhs data are for wide comparisons which can happen
 * on some platforms and with some compilers. 256 bit wide are coming to LLVM but not there
 * at present.
 */
#pragma pack (push, 1)
struct cmp_operands {
  ///First 64 bits of left hand side comparison data
  uint64_t v0;
  ///Second 64 bits of left hand side comparison data (wide comparisons only)
  uint64_t v0_128;
  ///Third 64 bits of left hand side comparison data (very wide comparisons only)
  uint64_t v0_256_0;
  ///Fourth 64 bits of left hand side comparison data (very wide comparisons only)
  uint64_t v0_256_1;

  ///First 64 bits of right hand side comparison data
  uint64_t v1;
  ///Second 64 bits of right hand side comparison data (wide comparisons only)
  uint64_t v1_128;
  ///Third 64 bits of right hand side comparison data (very wide comparisons only)
  uint64_t v1_256_0;
  ///Fourth 64 bits of right hand side comparison data (very wide comparisons only)
  uint64_t v1_256_1;

  ///Unused
  uint8_t unusued[8];
};
#pragma pack (pop)

/**
 * @brief Used for function logs
 * Not yet supported.
 */
#pragma pack (push, 1)
struct cmpfn_operands {
  ///Left side comparison data for function call instrumentation.
  uint8_t v0[32];
  ///Right side comparison data for function call instrumentation.
  uint8_t v1[32];

  ///Length of left side comparison data
  uint8_t v0_len;
  /// Length of right side of comparison data
  uint8_t v1_len;

  ///Unused
  uint8_t unusued[8];
};
#pragma pack (pop)

typedef struct cmp_operands cmp_map_list[CMP_MAP_H];

/**
 * @brief The cmp_map structure maintains a record of the dynamic comparisons that were performed by the program.
 * 
 * The map is split into two sections: a small one for headers, and a much larger one for the log itself. 
 * The index that is selected for a particular comparison (from hereon called k) is based on a hash of the 
 * compare instruction's address. Like the coverage map, this means collisions are possible and two separate 
 * comparison operations may share a header bucket a the same k .
 */
struct cmp_map {

  ///The header section
  struct cmp_header   headers[CMP_MAP_W]; 
  ///The log itself, which is most of the data
  struct cmp_operands log[CMP_MAP_W][CMP_MAP_H]; 

};
}
#endif
