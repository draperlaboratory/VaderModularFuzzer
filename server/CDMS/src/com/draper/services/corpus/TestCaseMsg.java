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

public class TestCaseMsg
{
    private String   tags    = ""; // Json Array of tags
    private String   clusterId;
    private String   scenarioId;
    private String   vmfId;
    private byte[]   data;
    private int      size;
    private String   fileType = "";
    
    public TestCaseMsg(int size)
    {
        setSize(size);       
        this.data = new byte[size];           
    }
 
    public TestCaseMsg(TestCaseMsg clone, int size)
    {
        this.tags           = clone.getTags();
        this.clusterId      = clone.getClusterId();
        this.scenarioId     = clone.getScenarioId();
        this.vmfId          = clone.getVmfId();
        this.size           = size;
        this.data           = new byte[size];           
    }
  
    public int getSize()
    {
        return size;
    }

    public void setSize(int size)
    {
        this.size = size;
    }

    public String getTags()
    {
        return tags;
    }
    public void setTags(String tags)
    {
        this.tags = tags;
    }
    public byte[] getData()
    {
        return data;
    }
    public void setData(byte[] data)
    {
        this.data = data;
    }

    public String getClusterId()
    {
        return clusterId;
    }

    public void setClusterId(String clusterId)
    {
        this.clusterId = clusterId;
    }

    public String getScenarioId()
    {
        return scenarioId;
    }

    public void setScenarioId(String scenarioId)
    {
        this.scenarioId = scenarioId;
    }

    public String getVmfId()
    {
        return vmfId;
    }

    public void setVmfId(String vmfId)
    {
        this.vmfId = vmfId;
    }

    public String getFileType()
    {
        return fileType;
    }
    
    public void setFileType(String fileType)
    {
        this.fileType = fileType;
    }
}