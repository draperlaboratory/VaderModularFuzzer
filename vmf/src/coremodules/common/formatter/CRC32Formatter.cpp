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
#include "CRC32Formatter.hpp"
#include "Logging.hpp"

using namespace vader;

#include "ModuleFactory.hpp"
REGISTER_MODULE(CRC32Formatter);

#define POLYNOMIAL 0xD8  /* 11011 followed by 0's */

/**
 * @brief Builder method to support the ModuleFactory
 * Constructs an instance of this class
 * @return Module* 
 */
Module* CRC32Formatter::build(std::string name)
{
    return new CRC32Formatter(name);
}

/**
 * @brief Initialization method
 * Reads in all configuration options for this class
 * 
 * @param config 
 */
void CRC32Formatter::init(ConfigInterface& config)
{
    initCRCLookupTable();

    isBigEndian = true;
    int num = 1;
    if(*(char *)&num == 1)
    {
        isBigEndian = false;
    }

}

/**
 * @brief Construct a new CRC32Formatter object
 * 
 * @param name the name of the module
 */
CRC32Formatter::CRC32Formatter(std::string name) : FormatterModule(name)
{
 
}

CRC32Formatter::~CRC32Formatter()
{

}

int CRC32Formatter::modifyTestCase(char* inputBuff, int inputBuffSize, char* outputBuff, int outputBuffSize)
{
    //The buffer not being large enough is improbable for this formatter, but worth checking anyway
    if(outputBuffSize < inputBuffSize + 4)
    {
        LOG_ERROR << "OutputBuffSize=" << outputBuffSize << ", InputBuffSize=" << inputBuffSize;
        throw RuntimeException("OutputBuffSize not large enough for formatter", RuntimeException::USAGE_ERROR);
    }

    memcpy((void*)outputBuff, (void*)inputBuff, inputBuffSize);

    crc checksum = computeChecksum((uint8_t*)outputBuff, inputBuffSize);

    int size = inputBuffSize;
    if(isBigEndian)
    {
        outputBuff[size++] = checksum >> 24; //byte 0
        outputBuff[size++] = checksum >> 16; //byte 1
        outputBuff[size++] = checksum >> 8; //byte 2
        outputBuff[size++] = checksum; //byte 3
    }
    else
    {
        //Little Endian
        outputBuff[size++] = checksum; //byte 3
        outputBuff[size++] = checksum >> 8; //byte 2
        outputBuff[size++] = checksum >> 16; //byte 1
        outputBuff[size++] = checksum >> 24; //byte 0
    }

    return size;

}

/**
 * @brief Helper method to initialize lookup table
 * 
 * From https://barrgroup.com/Embedded-Systems/How-To/CRC-Calculation-C-Code
 *
 */
void CRC32Formatter::initCRCLookupTable()
{
    crc remainder;

    /*
     * Compute the remainder of each possible dividend.
     */
    for (int dividend = 0; dividend < 256; ++dividend)
    {
        /*
         * Start with the dividend followed by zeros.
         */
        remainder = dividend << (WIDTH - 8);

        /*
         * Perform modulo-2 division, a bit at a time.
         */
        for (uint8_t bit = 8; bit > 0; --bit)
        {
            /*
             * Try to divide the current data bit.
             */			
            if (remainder & TOPBIT)
            {
                remainder = (remainder << 1) ^ POLYNOMIAL;
            }
            else
            {
                remainder = (remainder << 1);
            }
        }

        /*
         * Store the result into the table.
         */
        crcTable[dividend] = remainder;
    }
}

/**
 * @brief Helper method to compute CRC32 checksum
 * 
 * From https://barrgroup.com/Embedded-Systems/How-To/CRC-Calculation-C-Code
 * 
 * @param buff 
 * @param size 
 * @return CRC32Formatter::crc 
 */
CRC32Formatter::crc CRC32Formatter::computeChecksum(uint8_t* message, int nBytes)
{
    uint8_t data;
    crc remainder = 0xFFFFFFFF;

    /*
     * Divide the message by the polynomial, a byte at a time.
     */
    for (int byte = 0; byte < nBytes; ++byte)
    {
        data = message[byte] ^ (remainder >> (WIDTH - 8));
        remainder = crcTable[data] ^ (remainder << 8);
    }

    /*
     * The final remainder is the CRC.
     */
    return (remainder ^ 0xFFFFFFFF);

}