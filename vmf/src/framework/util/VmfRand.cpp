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

#include "VmfRand.hpp"
#include "Logging.hpp"

using namespace vmf;

VmfRand::VmfRand() {
  
}

/**
 * @brief Returns the singleton instance of VmfRand
 * 
 * @return VmfRand* the instance
 */
VmfRand* VmfRand::getInstance()
{
    static VmfRand instance; 
    return &instance;
}

/**
 * @brief Initialize random generator for a uniform random
 * distribution using the seed provided
 *
 * @param seed the random seed 
 */
void VmfRand::initSeed(unsigned seed) {
  LOG_INFO << "VMF initialized with random seed=" << seed;
  this->gen.seed(seed);
}

/**
 * @brief Initializes VmfRand random device and generator to support
 * subsequent calls to randomness access functions.  Without a random
 * seed specified, fetch one from the VmfRand random device
 */
void VmfRand::randInit() {
  initSeed(rd());
}

/**
 * @brief Initializes VmfRand random device and generator to support
 * subsequent calls to randomness access functions.
 */
void VmfRand::reproducibleInit(unsigned seed) {
  initSeed(seed);
}

/**
 * @brief Generate a random value between provided upper (inclusive)
 * and lower (inclusive) bounds.
 *
 * @param min the lower bound
 * @param max the upper bound
 * @return Random 64-bit value
 */
uint64_t VmfRand::randBetween(uint64_t min, uint64_t max) {
  return min + randBelow(max - min + 1);
}

/**
 * @brief Generate and return a random value lower than the limit (exclusive).
 * 
 * @param limit the upper bound
 * @return Random 64-bit value below upper bound
 */
uint64_t VmfRand::randBelow(uint64_t limit) {
  if (limit <= 1) { return 0; }

  std::uniform_int_distribution<> bounds(VMF_RANDMIN, limit-1);
  return bounds(this->gen);
}
