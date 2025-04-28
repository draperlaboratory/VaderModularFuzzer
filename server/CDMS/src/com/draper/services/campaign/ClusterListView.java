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

import com.draper.services.database.ClusterBean;

/***********************************************
 * 
 * @author
 *
 ***********************************************/
public class ClusterListView  implements Comparable<ClusterListView>
{
    private int                     clusterId;
    private String                  title;
    private String                  description;
    private String                  updated;
    private int                     scenarioCount;
    private int                     corpusSize;
    private int                 	vmfCount;
    private String                  state;
      
    public ClusterListView(ClusterBean cluster)
    {
        this.setClusterId(cluster.getId());
        this.setTitle(cluster.getName());
        this.setUpdated(cluster.getEdit());
        this.setDescription(cluster.getDescription());
        this.setState(cluster.getState());
        this.setCorpusSize(0);
    }

    public int getScenarioCount() 
    {
		return scenarioCount;
	}

	public void setScenarioCount(int scenarioCount) 
	{
		this.scenarioCount = scenarioCount;
	}

	public int getClusterId()
    {
        return clusterId;      
    }

    public void setClusterId(int cId)
    {
        this.clusterId = cId;
    }

    public String getTitle()
    {
        return title;
    }

    public void setTitle(String title)
    {
        this.title = title;
    }

    public String getDescription()
    {
        return description;
    }

    public void setDescription(String description)
    {
        this.description = description;
    }

    public String getUpdated()
    {
        return updated;
    }

    public void setUpdated(String updated)
    {
        this.updated = updated;
    }

    public int getVmfCount()
    {
        return vmfCount;
    }

    public void setVmfCount(int vmfCount)
    {
        this.vmfCount = vmfCount;
    }

    @Override
    public int compareTo(ClusterListView arg0)
    {
        int c1      = this.getClusterId();
        int c2      = arg0.getClusterId();
      
        if(c2 > c1)     return 1;
        else if(c2 <c1) return -1;
      
        return 0;
    }

    public String getState()
    {
        return state;
    }

    public void setState(String state)
    {
        this.state = state;
    }

    public int getCorpusSize()
    {
        return corpusSize;
    }

    public void setCorpusSize(int corpusSize)
    {
        this.corpusSize = corpusSize;
    }
}
