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
/* 
 * Declarations for vmfFrida runtime library for use by VMF module 
 *
 * Represents the operational interface between vmfFrida runtime library and 
 * a user/supplier of data.
 */

namespace vmfFrida_rt {
    const int FRIDA_STATUS_OK = 0;
    const int FRIDA_STATUS_HUNG = 1;
    const int FRIDA_STATUS_CRASHED = 2;
    const int FRIDA_STATUS_ERROR = 3;
    const int FRIDA_STATUS_UNKNOWN = 4;
    
    const int FRIDA_RT_VERSION = 0x00010000;
    const int FRIDA_RT_READY = 0xDEADBEEF;
    const int FRIDA_RT_DONE = 0xC0FFEE;
    const int FRIDA_RT_NEXT = 0xFEEDC0DE;
    const int FRIDA_RT_GO = 0xDECAFBAD;
};

