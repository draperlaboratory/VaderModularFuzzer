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
#include "RuntimeException.hpp"

using namespace vmf;
/**
 * @brief Construct a new Runtime Exception object
 * 
 * @param reason a description of the cause of the error
 * @param errCode the reason code
 */
RuntimeException::RuntimeException(const char* reason, ErrorCodeEnum errCode) :
    BaseException(reason),
    myErrorCode(errCode)
{
    //empty
}

/**
 * @brief Sets the error code on the exception
 * 
 * @param e the error code
 */
void RuntimeException::setErrorCode(ErrorCodeEnum e)
{
    myErrorCode = e;
}

/**
 * @brief Gets the error code from the exception
 * 
 * @return RuntimeException::ErrorCodeEnum 
 */
RuntimeException::ErrorCodeEnum RuntimeException::getErrorCode()
{
    return myErrorCode;
}