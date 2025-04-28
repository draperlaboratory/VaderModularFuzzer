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

public class CorpusBean
{
    private int                           id;
    private int                           clusterId;
    private int                           scenarioId;
    private long                          timestamp;
    
    public CorpusBean()
    {
      this.clusterId  = 0;
      this.scenarioId = 0;
      this.timestamp  = 0;      
    }
    
    public CorpusBean( int clusterId, int scenarioId, long timestamp )
    {
        this.clusterId  = clusterId;
        this.scenarioId = scenarioId;
        this.timestamp  = timestamp;
    }
    
    public int getId()
    {
        return id;
    }
    public void setId(int id)
    {
        this.id = id;
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
    public long getTimestamp()
    {
        return timestamp;
    }
    public void setTimestamp(long timestamp)
    {
        this.timestamp = timestamp;
    }
 
}