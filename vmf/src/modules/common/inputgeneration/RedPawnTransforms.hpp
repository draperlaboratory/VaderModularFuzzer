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

//#include <unordered_set> // for printing each unique pattern if verbose debugging is needed
#include <cstdint>

namespace vmf
{

    
/**
 * @brief A RedPawnTransform represents a type of input-to-state correspondence
 * that RedPawn can search for. An encoding transform provides an encoding and a 
 * decoding routine, enabling RedPawn to detect and reverse encodings between input
 * data and program state.
 */
class RedPawnEncodingTransform
{
public:
    /**
     * @brief Decoding routine for this transform
     * 
     * @param input 
     * @param size 
     * @return uint64_t the transformed value
     */
    virtual uint64_t Decode(uint64_t input, int size) = 0;
    /**
     * @brief Encoding routing for this transform
     * 
     * @param input 
     * @param size 
     * @return uint64_t the transformed value
     */
    virtual uint64_t Encode(uint64_t input, int size) = 0;
    virtual ~RedPawnEncodingTransform(){}
};

/**
 * @brief An arithmetic transform represents a transform that requires a parameter
 * that must be solved, for example addition of a constant in the relationship between
 * input data and program state. An arithmetic transform is given two input/output pairs
 * and must detect a pattern, then perform the reverse of the pattern on sample_out to create
 * sample_in. It returns true or false depending on whether a pattern is actually detected and
 * sample_in is valid.
 */
class RedPawnArithmeticTransform
{
public:
    /**
     * @brief Main method for all arithmetic transforms
     * 
     * @param input1 
     * @param output1 
     * @param input2 
     * @param output2 
     * @param sample_in 
     * @param sample_out 
     * @param size 
     * @return true if the transform detects a pattern in the input
     */
    virtual bool SolveTransform(uint64_t input1, uint64_t output1, uint64_t input2, uint64_t output2, uint64_t& sample_in, uint64_t sample_out, int size) = 0;
    virtual ~RedPawnArithmeticTransform(){}
    //std::unordered_set<uint64_t> matchLog;
};

/**
 * @brief Empty encoding transform that does not modify the input at all.
 * 
 */
class DirectTransform : public RedPawnEncodingTransform
{
    uint64_t Decode(uint64_t input, int size);
    uint64_t Encode(uint64_t input, int size);
};

/**
 * @brief Encoding transform that reverses the bytes from the input.
 * 
 */
class ReverseBytesTransform : public RedPawnEncodingTransform
{
    uint64_t Decode(uint64_t input, int size);
    uint64_t Encode(uint64_t input, int size);
};



/**
 * @brief Arithmetic transform that tests if there is a constant +/- relationship between input and output
 */
class OffsetTransform : public RedPawnArithmeticTransform
{
public:
    bool SolveTransform(uint64_t input1, uint64_t output1, uint64_t input2, uint64_t output2, uint64_t& sample_in, uint64_t sample_out, int size);
};

/**
 * @brief Arithmetic transform that tests if there is a multiplicant relationship between input and output
 */
class FactorTransform : public RedPawnArithmeticTransform
{
    bool SolveTransform(uint64_t input1, uint64_t output1, uint64_t input2, uint64_t output2, uint64_t& sample_in, uint64_t sample_out, int size);
};

/**
 * @brief Arithmetic transform that tests if there is a xor relationship between input and output
 * 
 */
class XORTransform : public RedPawnArithmeticTransform
{
    bool SolveTransform(uint64_t input1, uint64_t output1, uint64_t input2, uint64_t output2, uint64_t& sample_in, uint64_t sample_out, int size);
};


}
