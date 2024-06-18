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
#include <string>
#include "RedPawnTransforms.hpp"
#include "Logging.hpp"

using namespace vmf;

/**
 * @brief Creates a bitmask that can select out a provided number of bytes. Max is 64 bits.
 */
uint64_t RedPawnSizeToMask(int size)
{
    uint64_t mask = 0;
    switch (size)
    {
    case 1:
        mask = 0xFF;
        break;
    case 2:
        mask = 0xFFFF;
        break;
    case 3:
    case 4:
        mask = 0xFFFFFFFF;
        break;
    case 5:
    case 6:
    case 7:
    case 8:
    default:
        mask = 0xFFFFFFFFFFFFFFFFL;
        break;
    }

    return mask;
}

/**
 * @brief The empty transform
 */
uint64_t DirectTransform::Encode(uint64_t input, int size)
{
    return input;
}

uint64_t DirectTransform::Decode(uint64_t input, int size)
{
    return input;
}

/**
 * @brief Flip bytes transform
 */
uint64_t ReverseBytesTransform::Encode(uint64_t input, int size)
{
    uint64_t result = 0;

    char * src = (char *) &input;
    char * dst = (char *) &result;

    for (int i = 0; i < size; i++)
    {
        dst[size - i - 1] = src[i];
    }

    return result;
}

uint64_t ReverseBytesTransform::Decode(uint64_t input, int size)
{
    // Symmetric
    return Encode(input, size);
}

/**
 * @brief Offset Arithmetic Transformation
 *        Test if there is a constant +/- relationship between input and output
 */
bool OffsetTransform::SolveTransform(uint64_t input1, uint64_t output1, uint64_t input2, uint64_t output2, uint64_t& sample_in, uint64_t sample_out, int size)
{

    uint64_t mask = RedPawnSizeToMask(size);
    int64_t diff1 = mask & (output1 - input1);
    int64_t diff2 = mask & (output2 - input2);

    // If these are the same, we have a hit.
    if (diff1 != 0 && diff1 == diff2)
    {
        // Reverse transform on sample output to solve for input
        sample_in = sample_out - diff1;

        // Print each match once
        /*
        if (matchLog.find(diff1) == matchLog.end())
        {
            LOG_INFO << "Arithmetic hit of " << diff1;
            matchLog.insert(diff1);
        }
        */
        return true;
    }
    return false;
}

/**
 * @brief Factor Arithmetic Transformation
 *        Test if there is a multiplicant relationship between input and output
 */
bool FactorTransform::SolveTransform(uint64_t input1, uint64_t output1, uint64_t input2, uint64_t output2, uint64_t& sample_in, uint64_t sample_out, int size)
{
    // Can't divide by 0, so skip transform if that would be needed
    if (input1 == 0 || input2 == 0)
        return false;
    
    int64_t fact1 = output1 / input1;
    int64_t fact2 = output2 / input2;

    // If these are the same, we have a hit.
    if (fact1 !=0 && fact1 != 1 && fact1 == fact2)
    {

        // Reverse transform on sample output to solve for input
        sample_in = sample_out / fact1;

        // Print each match once
        /*
        if (matchLog.find(fact1) == matchLog.end())
        {
            LOG_INFO << "Multiplicant hit of " << fact1;
            matchLog.insert(fact1);
        }
        */
        return true;
    }
    return false;
}

/**
 * @brief Xor Arithmetic Transformation
 *        Test if there is a xor relationship between input and output
 */
bool XORTransform::SolveTransform(uint64_t input1, uint64_t output1, uint64_t input2, uint64_t output2, uint64_t& sample_in, uint64_t sample_out, int size)
{
    int64_t pattern1 = output1 ^ input1;
    int64_t pattern2 = output2 ^ input2;

    // If these are the same, we have a hit.
    if (pattern1 != 0 && pattern1 == pattern2)
    {

        // Reverse transform on sample output to solve for input
        sample_in = sample_out ^ pattern1;

        // Print each match once
        /*
        if (matchLog.find(pattern1) == matchLog.end())
        {
            LOG_INFO << "XOR hit of " << std::hex << pattern1;
            matchLog.insert(pattern1);
        }
        */
        return true;
    }
    return false;
}
