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
package com.draper.utilities;

import java.util.ArrayList;
import java.util.Date;

import com.google.gson.Gson;

public class SystemEvent
{
    private          String                 time        	= null;
    private          String                 description 	= null;
    private  static  ArrayList<SystemEvent> eventDB     	= new  ArrayList<SystemEvent>();
    
    SystemEvent( String time, String description )
    {
        this.time        = time;
        this.description = description;  
    }
    
    public static void add(String description)
    {
        eventDB.add(new SystemEvent( UiUtil.fmtDate( new Date(), UiUtil.FULL_TIMESTAMP_FORMAT), description ));
    }
    
    public static String toJSON()
    {
        Gson   gson     = new Gson();
        String result   = gson.toJson(eventDB);
                
        return result;        
    }
 
    public static ArrayList<SystemEvent> getEvents()
    {
        return eventDB;
    }
    
    public String getTime()
    {
        return time;
    }
    public void setTime(String time)
    {
        this.time = time;
    }
    public String getDescription()
    {
        return description;
    }
    public void setDescription(String description)
    {
        this.description = description;
    }  
}
