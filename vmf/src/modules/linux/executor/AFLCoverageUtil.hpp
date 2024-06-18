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
/*
   american fuzzy lop++ - fuzzer code
   --------------------------------

   Originally written by Michal Zalewski

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                        Heiko Eißfeldt <heiko.eissfeldt@hexco.de> and
                        Andrea Fioraldi <andreafioraldi@gmail.com>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2022 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   This is the real deal: the program takes an instrumented binary and
   attempts a variety of basic fuzzing tricks, paying close attention to
   how they affect the execution path.

 */


#pragma once

#include <stdint.h>
#include <unistd.h>
#include <string.h>

#if !defined(_COUNT_CLASS_H)
#define _COUNT_CLASS_H

#if defined(__cplusplus)
    extern "C" {
#endif
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


namespace vmf {

/**
 * @brief Set of utiity functions to interact with AFL-based coverage bitmaps
 */
class AFLCoverageUtil {

private:
    uint16_t count_class_lookup[65536];
    uint8_t simplify_lookup[256];
  
    void initCountClassLookup() {
        uint8_t lookup8[256];
        lookup8[0] = 0;
        lookup8[1] = 1;
        lookup8[2] = 2;
        lookup8[3] = 4;
        for (int i = 4; i <= 7; i++)
            lookup8[i] = 8;
        for (int i = 8; i <= 15; i++)
            lookup8[i] = 16;
        for (int i = 16; i <= 31; i++)
            lookup8[i] = 32;
        for (int i = 32; i <= 127; i++)
            lookup8[i] = 64;
        for (int i = 128; i <= 255; i++)
            lookup8[i] = 128;

        for (int b1 = 0; b1 < 256; b1++) 
            for (int b2 = 0; b2 < 256; b2++) 
                count_class_lookup[(b1 << 8) + b2] =
                    (lookup8[b1] << 8) | lookup8[b2];
    }

    void initSimplifyLookup() {
        simplify_lookup[0] = 1;
        for (int i = 1; i <= 255; i++)
            simplify_lookup[i] = 128;
    }

public:
    AFLCoverageUtil() {
        initCountClassLookup();
        initSimplifyLookup();
    }

    /**
     * @brief Iterate through all 8-bit raw tuple counts in the coverage
     * map and "classify" them by transforming them in place from 8-bit
     * counters to 8-bit buckets that record coverage progress. 
     *
     * @param trace Pointer to the coverage map
     * @param map_size Size of the coverage map in bytes
     */
    void classifyCounts(uint8_t *trace, uint32_t map_size);

    /**
     * @brief Given a 64-bit word, "classify" each 8-bit block using a
     * lookup table to find the bucket value that corresponds to the raw
     * tuple coverage count.
     *
     * @param word Value corresponding to a set raw coverage counts
     * @return uint64_t Classified bucket representation of the coverage counts
     */
    uint64_t classifyWord(uint64_t word);

    /**
     * @brief Count the number of bytes set in a coverage bitmap
     *
     * @param trace Pointer to coverage map
     * @param map_size Size of coverage map in bytes
     * @return uint32_t Byte-count
     */
    uint32_t countBytes(uint8_t* trace, uint32_t map_size);

    /**
     * @brief Count the number of non-255 bytes set in the bitmap. 
     * A byte in the with the value 255 may correspond to empty counts or impending overflow,
     * hence, ignored.
     *
     * @param virgin Pointer to the  virgin bitmap that corresponds to
     * cumulative coverage
     * @param map_size Size of the coverage map in bytes
     * @return uint32_t Number of non-255 bytes found
     */
    uint32_t countNon255Bytes(uint8_t *virgin, uint32_t map_size);

    /**
     * @brief Updates a 64-bit value from a virgin bitmap with a value
     * from a recent trace. Return value in pointer indicates whether (1) a change
     * in a hit-count is found or (2) a new control-flow edge (tuple) is found
     * 
     *
     * @param[out] ret return value, (1) new hit count, (2) new tuple found
     * @param current pointer to recent trace bits
     * @param virgin pointer to virgin bits 
     */
    void discoverWord(uint8_t* ret, uint64_t *current, uint64_t *virgin);

    /**
     * @brief Updates virgin bitmap with coverage data from recentr trace.
     * Returns 1 if new hit counts are discovered, 2 if new control-flow edges
     * (tuples) are found 
     *
     * @param trace Pointer to coverage bitmap from recent test
     * @param virgin Poiner to virgin bitmap with cumulative coverage
     * @param map_size Size of bitmaps in bytes
     * @return uint8_t Value indicating new coverage type: (1) hit counts, (2) new edges
     */
    uint8_t hasNewBits(uint8_t *trace, uint8_t *virgin, uint32_t map_size);

    /**
     * @brief Classifies counts from recent test coverage bitmap, updates
     * virgin bits, and returns new coverage status similar to hasNewBits
     *
     * @param trace Pointer to coverage bitmap from recent test
     * @param virgin Poiner to virgin bitmap with cumulative coverage
     * @param map_size Size of bitmaps in bytes
     * @return uint8_t Value indicating new coverage type: (1) hit counts, (2) new edges
     */
    uint8_t hasNewBitsUnclassified(uint8_t *trace, uint8_t *virgin, uint32_t map_size);

    /**
     * @brief Collapse coverage trace by summarizing hit-counts to binary,
     * hit or not-hit values.  
     *
     * @param bytes Pointer to coverage map
     * @param map_size Size of coverage map in bytes
     */
    void simplifyTrace(uint8_t *bytes, uint32_t map_size);

    /**
     * @brief Quickly skim through recent coverage trace while comparing
     * to virgin bitmap for new trace data.
     *
     * @param virgin Pointer to virgin bitmap
     * @param current Pointer to coverage bitmap from recent test
     * @param current_end Pointer to end of recent coverage bitmap (current + map_size)
     * @return uint32_t (1) New coverage, (0) No new coverage 
     */
    uint32_t skim(const uint64_t *virgin, const uint64_t *current, const uint64_t *current_end); 
};
}

#if defined(__cplusplus)
};
#endif

#endif
