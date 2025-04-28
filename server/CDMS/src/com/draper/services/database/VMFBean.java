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
package com.draper.services.database;

public class VMFBean
{
    private int    uid;
    private int    pid;
    private int    clusterId;
    private int    scenarioId;
    private String name;
    private String host;
    private String kpi;
    private int    status;
    private String reason;

    public VMFBean()
    {
        this.name           = "NA";
        this.kpi            = "NA";
        this.uid            = 0;
        this.pid            = 0;;
        this.host           = "NA";
         this.clusterId     = 0;
        this.scenarioId     = 0;
        this.status         = 0;
        this.reason         = "NA";
    }

    public String getName()
    {
        return name;
    }

    public void setName(String name)
    {
        this.name = name;
    }

    public String getJson()
    {
        return kpi;
    }

    public void setJson(String json)
    {
        this.kpi = json;
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

    public String getHost()
    {
        return host;
    }

    public void setHost(String host)
    {
        this.host = host;
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

    public int getStatus()
    {
        return status;
    }

    public void setStatus(int status)
    {
        this.status = status;
    }

    public String getReason()
    {
        return reason;
    }

    public void setReason(String reason)
    {
        this.reason = reason;
    }
}