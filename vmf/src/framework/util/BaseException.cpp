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
#include "BaseException.hpp"

using namespace vmf;
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
BaseException::BaseException(std::string reason)
{
    setReason(reason);
}

/**
 * @brief Returns the exception reason
 *
 * @return std::string the reason
 */
std::string BaseException::getReason() const
{
    return myReason;
}

/**
 * @brief Sets the exception reason
 *
 * @param reason the reason
 */
void BaseException::setReason(std::string reason)
{
    myReason = reason;
}