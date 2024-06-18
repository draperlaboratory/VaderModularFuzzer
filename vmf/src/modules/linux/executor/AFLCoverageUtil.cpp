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

// Modified for VMF, copyright Draper Laboratory 2024

#include "AFLCoverageUtil.hpp"

#include <stdlib.h>

using namespace vmf;

void AFLCoverageUtil::classifyCounts(uint8_t *trace, uint32_t map_size) {
    uint64_t *mem64 = (uint64_t *)trace;
    uint32_t i = map_size >> 3;
    while (i--) {
        /* Optimize for sparse bitmaps. */
        if (unlikely(*mem64))
            *mem64 = classifyWord(*mem64); 

        mem64++;
    }
}

uint64_t AFLCoverageUtil::classifyWord(uint64_t word) {
    uint16_t mem16[4];
    memcpy(mem16, &word, sizeof(mem16));

    mem16[0] = count_class_lookup[mem16[0]];
    mem16[1] = count_class_lookup[mem16[1]];
    mem16[2] = count_class_lookup[mem16[2]];
    mem16[3] = count_class_lookup[mem16[3]];

    memcpy(&word, mem16, sizeof(mem16));
    return word;
}

uint32_t AFLCoverageUtil::countBytes(uint8_t* trace, uint32_t map_size) {
    uint32_t *ptr = (uint32_t *)trace;
    uint32_t i = map_size / 4;
    uint32_t ret = 0;

    while (i--) {
        uint32_t v = *(ptr++);
        if (likely(!v)) { continue; }
        if (v & 0x000000ffU) { ++ret; }
        if (v & 0x0000ff00U) { ++ret; }
        if (v & 0x00ff0000U) { ++ret; }
        if (v & 0xff000000U) { ++ret; }
    }

    return ret;
}

uint32_t AFLCoverageUtil::countNon255Bytes(uint8_t *virgin, uint32_t map_size) {
    uint32_t *ptr = (uint32_t *)virgin;
    uint32_t i = map_size / 4;
    uint32_t ret = 0;

    while (i--) {
        uint32_t v = *(ptr++);
        /* This is called on the virgin bitmap, so optimize for the most likely
           case. */
        if (likely(v == 0xffffffffU)) { continue; }
        if ((v & 0x000000ffU) != 0x000000ffU) { ++ret; }
        if ((v & 0x0000ff00U) != 0x0000ff00U) { ++ret; }
        if ((v & 0x00ff0000U) != 0x00ff0000U) { ++ret; }
        if ((v & 0xff000000U) != 0xff000000U) { ++ret; }
    }
    return ret;
}

void AFLCoverageUtil::discoverWord(uint8_t* ret, uint64_t *current, uint64_t *virgin) {
    /* Optimize for (*current & *virgin) == 0 - i.e., no bits in current bitmap
       that have not been already cleared from the virgin map - since this will
       almost always be the case. */
    if (*current & *virgin) {
        if (likely(*ret < 2)) {
            uint8_t *cur = (uint8_t *)current;
            uint8_t *vir = (uint8_t *)virgin;

            /* Looks like we have not found any new bytes yet; see if any non-zero
               bytes in current[] are pristine in virgin[]. */
            if ((cur[0] && vir[0] == 0xff) || (cur[1] && vir[1] == 0xff) ||
                (cur[2] && vir[2] == 0xff) || (cur[3] && vir[3] == 0xff) ||
                (cur[4] && vir[4] == 0xff) || (cur[5] && vir[5] == 0xff) ||
                (cur[6] && vir[6] == 0xff) || (cur[7] && vir[7] == 0xff))
                *ret = 2;
            else
                *ret = 1;
        }
        *virgin &= ~*current;
    }
}

uint8_t AFLCoverageUtil::hasNewBits(uint8_t *trace, uint8_t *_virgin, uint32_t map_size) {
    uint64_t *current = (uint64_t *)trace;
    uint64_t *virgin = (uint64_t *)_virgin;

    uint32_t i = (map_size + 7) >> 3;
    uint8_t ret = 0;

    while (i--) {
        if (unlikely(*current))
            discoverWord(&ret, current, virgin);

        current++;
        virgin++;
    }

    return ret;
}

uint32_t AFLCoverageUtil::skim(const uint64_t *virgin, const uint64_t *current, const uint64_t *current_end) {
    for (; current < current_end; virgin += 4, current += 4) {
        if (unlikely(current[0] && classifyWord(current[0]) & virgin[0])) return 1;
        if (unlikely(current[1] && classifyWord(current[1]) & virgin[1])) return 1;
        if (unlikely(current[2] && classifyWord(current[2]) & virgin[2])) return 1;
        if (unlikely(current[3] && classifyWord(current[3]) & virgin[3])) return 1;
    }
    return 0;
}

uint8_t AFLCoverageUtil::hasNewBitsUnclassified(uint8_t *trace, uint8_t *virgin, uint32_t map_size) {
    uint8_t *end = trace + map_size;

    if (!skim((uint64_t *)virgin, (uint64_t *)trace, (uint64_t *)end))
        return 0;

    classifyCounts(trace, map_size);
    return hasNewBits(trace, virgin, map_size);
}
void AFLCoverageUtil::simplifyTrace(uint8_t *trace, uint32_t map_size) {
    uint64_t *mem64 = (uint64_t *)trace;
    uint32_t i = (map_size >> 3);

    while (i--) {
        /* Optimize for sparse bitmaps. */
        if (unlikely(*mem64)) {
            uint8_t *mem8 = (uint8_t *)mem64;
            mem8[0] = simplify_lookup[mem8[0]];
            mem8[1] = simplify_lookup[mem8[1]];
            mem8[2] = simplify_lookup[mem8[2]];
            mem8[3] = simplify_lookup[mem8[3]];
            mem8[4] = simplify_lookup[mem8[4]];
            mem8[5] = simplify_lookup[mem8[5]];
            mem8[6] = simplify_lookup[mem8[6]];
            mem8[7] = simplify_lookup[mem8[7]];
        } else {
            *mem64 = 0x0101010101010101ULL;
        }
        mem64++;
    }
}

