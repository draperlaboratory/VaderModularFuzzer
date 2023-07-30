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
#include "BaseException.hpp"

using namespace vader;
/**
 * @brief Construct a new Base Exception:: Base Exception object
 *
 */
BaseException::BaseException()
{
    myReason[0] = 0;
}

/**
 * @brief Construct a new Base Exception:: Base Exception object
 *
 * @param reason the exception reason
 */
BaseException::BaseException(const char* reason)
{
    setReason(reason);
}

/**
 * @brief Returns the exception reason
 *
 * @return const char* the reason
 */
const char* BaseException::getReason() const
{
    return myReason;
}

/**
 * @brief Sets the exception reason
 *
 * @param reason the reason
 */
void BaseException::setReason(const char* reason)
{
    strncpy( myReason, reason, MAX_REASON - 1 );
    myReason[MAX_REASON-1] = 0;
}