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
package com.draper.services.performance;

import java.util.ArrayList;

import com.draper.utilities.KVPair;

/***********************************************
 * Holds an Id and a set of data
 ***********************************************/
public class PerformanceData  
{
    private int                         id;
    private ArrayList<KVPair>           data;
    
    public PerformanceData( int id, ArrayList<KVPair> kv )
    {
        this.id   = id;
        this.data = kv;       
    }
    
    public int getId()
    {
        return id;
    }
    public void setId(int id)
    {
        this.id = id;
    }
    public ArrayList<KVPair> getData()
    {
        return data;
    }
    public void setData(ArrayList<KVPair> data)
    {
        this.data = data;
    }   
}