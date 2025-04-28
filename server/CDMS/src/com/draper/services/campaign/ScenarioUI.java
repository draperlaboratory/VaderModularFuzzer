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
package com.draper.services.campaign;

import java.util.ArrayList;

import com.draper.utilities.KVPair;

/***********************************************
 * 
 * @author
 *
 ***********************************************/
public class ScenarioUI  implements Comparable<ScenarioUI>
{
    private int                     Id;
    private String                  ScenarioName;
    private String                  VMFLink;
    private String                  Type;
    private int                     ActiveFuzzers;
    private String                  State;
    private int                     Capacity;
    private ArrayList<KVPair>       data;
    private String                  Action;
    
    public ScenarioUI()
    {
        this.Id             = 0;
        this.ScenarioName   = "";
        this.Type           = "";
        this.State          = "";
        this.ActiveFuzzers  = 0;
        this.VMFLink        = "";
        this.data           = new ArrayList<KVPair>();    
        this.Action         = "";
    }
    
    public String getAction()
    {
        return Action;
    }
    public void setAction(String action)
    {
        this.Action = action;
    }
    
    public String getScenarioName()
    {
        return ScenarioName;
    }
    public void setScenarioName(String scenarioName)
    {
        this.ScenarioName = scenarioName;
    }
    public String getVMFLink()
    {        
        return VMFLink;
    }
     
    public void setVMFLink(String scenarioName, int ScenarioId)
    {        
        this.VMFLink = "<a id='scenarioName' href='#' onclick=\"getVMFs('" +  ScenarioId + "')\">" + scenarioName +  "</a>";
    }
    
    public String getState()
    {
        return State;
    }
    public void setState(String state)
    {
        State = state;
    }
    public String getType()
    {
        return Type;
    }
    public void setType(String type)
    {
        Type = type;
    }
    public int getActiveFuzzers()
    {
        return ActiveFuzzers;
    }
    public void setActiveFuzzers(int vMFCount)
    {
        ActiveFuzzers = vMFCount;
    }
    public ArrayList<KVPair> getData()
    {
        return data;
    }
    public void setData(ArrayList<KVPair> data)
    {
        this.data = data;
    }

    public int getCapacity()
    {
        return Capacity;
    }

    public void setCapacity(int capacity)
    {
        Capacity = capacity;
    }

    public int getId()
    {
        return Id;
    }

    public void setId(int id)
    {
        Id = id;
    }
    
    @Override
    public int compareTo(ScenarioUI arg0)
    {   
        String T1      = this.getType();
        String T2      = arg0.getType();

        if( T1.equalsIgnoreCase("Fuzzer") && T2.equalsIgnoreCase("Analyzer"))
        {
            return -1;
        }
        if( T1.equalsIgnoreCase("Fuzzer") && T2.equalsIgnoreCase("Minimizer"))
        {
            return -1;
        }
        if( T1.equalsIgnoreCase("Analyzer") && T2.equalsIgnoreCase("Minimizer"))
        {
            return -1;
        }
        
        return 1;
    }

}
