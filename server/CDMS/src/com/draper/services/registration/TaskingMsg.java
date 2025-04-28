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

public class TaskingMsg
{
    private int                     clusterId;
    private int                     scenarioId;
    private int                     status;
    private String []               files;

    public TaskingMsg()
    {
        this.clusterId        = 0;
        this.scenarioId       = 0;
        this.files            = null;
        status                = StatusType.UNREGISTER.Id(); 
    }

  
    public int getClusterId() 
    {
        return clusterId;
    }

    public void setClusterId(int clusterId) 
    {
        this.clusterId = clusterId;
    }

    public String[] getFiles() 
    {
        return files;
    }

    public void setFiles(String[] files) 
    {
        this.files = files;
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
}