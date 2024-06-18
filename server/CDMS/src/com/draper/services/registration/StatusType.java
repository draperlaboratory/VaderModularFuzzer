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
package com.draper.services.registration;

public enum StatusType
{
    TASKED(1021),
    RUNNING(1022),
    FAILED(1023),
    IDLE(1024),
    UNREGISTER(1025),
    PAUSED(1026);
    
    private int id;  
    
    StatusType(int id) 
    {
       this.id = id;
    }
    
    public int Id() 
    { 
        return id; 
    }
    
    public static String toString(int id)
    {
        if( 1021 == id ) return "TASKED";
        if( 1022 == id ) return "RUNNING";
        if( 1023 == id ) return "FAILED";
        if( 1024 == id ) return "IDLE";
        if( 1025 == id ) return "UNREGISTER";
        if( 1026 == id ) return "PAUSED";
        
        return Integer.toString(id);
    }
}
  