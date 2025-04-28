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
  