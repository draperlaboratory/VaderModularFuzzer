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
package com.draper.services.corpus;

import java.util.Date;

import com.draper.services.database.TestCaseBean;
import com.draper.utilities.UiUtil;

/***********************************************
 * 
 * @author
 *
 ***********************************************/
public class TestCaseView
{
    private String                  scenario;
    private int                     id;
    private int                     scenarioId;
    private int                     clusterId;
    private String                  timestamp;
    private String                  filename;
    private String                  tags;
    
    public TestCaseView(int clusterId)
    {
        this.id             = 0;
        this.clusterId      = clusterId;
        this.scenarioId     = 0;
        this.timestamp      = java.time.LocalDate.now().toString();
        this.filename       = "NA";
        this.tags           = "NA";                    
        this.scenario       = "";                    
    }
   
    public TestCaseView( TestCaseBean tb, String name)
    {
        this.id             = tb.getId();
        this.scenarioId     = tb.getScenarioId();
        this.clusterId      = tb.getClusterId();
        this.scenario       = name;
        this.timestamp      = UiUtil.fmtDate(new Date(tb.getTimestamp()), UiUtil.TIMESTAMP_FORMAT );
        this.tags           = tb.getTags();                    

        setFilename(tb.getFilename());
    }
    
    public int getId()
    {
        return id;
    }
    public void setId(int id)
    {
        this.id = id;
    }
    public int getScenarioId()
    {
        return scenarioId;
    }
    public void setScenarioId(int scenarioId)
    {
        this.scenarioId = scenarioId;
    }
    public String getTimestamp()
    {
        return timestamp;
    }
    public void setTimestamp(String timestamp)
    {
        this.timestamp = timestamp;
    }
    public String getFilename()
    {
        return filename;
    }
    public void setFilename(String filename)
    {
        this.filename = filename;
        
        this.filename = "<a id='filename' href='#' onclick=\"downloadCorpusFile('" + this.scenarioId  + "','" + this.clusterId + "','" + this.filename + "')\">" + this.filename +  "</a>";

    }
    public String getTags()
    {
        return tags;
    }
    public void setTags(String tags)
    {
        this.tags = tags;
    }

    public int getClusterId()
    {
        return clusterId;
    }

    public void setClusterId(int clusterId)
    {
        this.clusterId = clusterId;
    }

    public String getScenario()
    {
        return scenario;
    }

    public void setScenario(String scenario)
    {
        this.scenario = scenario;
    }
}
    
