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

#pragma once

#include "StorageModule.hpp"
#include "RuntimeException.hpp"
#include "Logging.hpp"

#include <random>
#include <stdio.h>

#define VMF_RANDMIN 0
#define ARITH_MAX 35

namespace vmf {
  /**
   * @brief VMF's Random Number Generator
   */
  class VmfRand {
  private:
    VmfRand();
    std::random_device rd; 
    std::mt19937 gen;    

  public:
    static VmfRand*      getInstance();
    void initSeed(unsigned seed);
    void randInit(void);
    void reproducibleInit(unsigned seed);
    unsigned long randBetween(unsigned long min, unsigned long max);
    unsigned long randBelow(unsigned long limit);
    int randBetween(int min, int max);
    int randBelow(int limit);
    int randBelowExcept(int limit, int exception);
  };
}
