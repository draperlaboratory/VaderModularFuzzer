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

import com.draper.services.database.VMFBean;
import com.draper.services.registration.StatusType;
import com.draper.utilities.KVPair;

/***********************************************
 * 
 * @author
 *
 ***********************************************/
public class VmfUI  
{
    private int                 uid;
    private String              vmfName;
    private int                 pid;
    private int                 clusterId;
    private int                 scenarioId;
    private String              host;
    private ArrayList<KVPair>   data;
    private String              state;
    
    public VmfUI(VMFBean vb)
    {
        this.uid        = vb.getUid();
        this.pid        = vb.getPid();
        this.clusterId  = vb.getClusterId();
        this.scenarioId = vb.getScenarioId();
        this.vmfName    = vb.getName();
        this.host       = vb.getHost();       
        this.state      = "(" + StatusType.toString(vb.getStatus()) +"):" + vb.getReason(); 
        this.data       = new ArrayList<KVPair>();
    }
    public String getVmfName()
    {
        return vmfName;
    }
    public void setVmfName(String vmfName)
    {
        this.vmfName = vmfName;
    }
    public String getHost()
    {
        return host;
    }
    public void setHost(String host)
    {
        this.host = host;
    }
    public ArrayList<KVPair> getData()
    {
        return data;
    }
    public void setData(ArrayList<KVPair> data)
    {
        this.data = data;
    }
    public String getState()
    {
        return state;
    }
    public void setState(String state)
    {
        this.state = state;
    }
    public int getUid()
    {
        return uid;
    }
    public void setUid(int uid)
    {
        this.uid = uid;
    }
    public int getPid()
    {
        return pid;
    }
    public void setPid(int pid)
    {
        this.pid = pid;
    }
    public int getClusterId()
    {
        return clusterId;
    }
    public void setClusterId(int clusterId)
    {
        this.clusterId = clusterId;
    }
    public int getScenarioId()
    {
        return scenarioId;
    }
    public void setScenarioId(int scenarioId)
    {
        this.scenarioId = scenarioId;
    }
}
