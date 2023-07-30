/* =============================================================================
 * Vader Modular Fuzzer (VMF)
 * Copyright (c) 2021-2023 The Charles Stark Draper Laboratory, Inc.
 * <vader@draper.com>
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
#pragma once

#include "FormatterModule.hpp"

namespace vader
{
/**
 * @brief A simple formatter that appends a checksum to the test case
 * 
 * CRC algorithm is from https://barrgroup.com/Embedded-Systems/How-To/CRC-Calculation-C-Code
 */
class CRC32Formatter: public FormatterModule
{
public:
    static Module* build(std::string name);
    virtual void init(ConfigInterface& config);
    CRC32Formatter(std::string name);
    virtual ~CRC32Formatter();

    virtual int modifyTestCase(char* inputBuff, int inputBuffSize, char* outputBuff, int outputBuffSize);
private:
    typedef uint32_t crc;
    bool isBigEndian;
    void initCRCLookupTable();
    crc computeChecksum(uint8_t* message, int nBytes);

    #define WIDTH  (8 * sizeof(crc))
    #define TOPBIT (1 << (WIDTH - 1))
    crc crcTable[256];
};
}
    