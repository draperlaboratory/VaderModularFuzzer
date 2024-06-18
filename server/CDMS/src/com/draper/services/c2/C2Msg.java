/* =============================================================================
 * Vader Modular Fuzzer (VMF)
 * Copyright (c) 2021-2024 The Charles Stark Draper Laboratory, Inc.
 * <vmf@draper.com>
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
package com.draper.services.c2;


public class C2Msg
{
	private int                     commandId;
    private int                     uid;
    private int                     clusterId;
    private int                     scenarioId;

    public C2Msg()
    {
        this.uid              = 0;
        this.clusterId        = 0;
        this.scenarioId       = 0;
        this.commandId        = 0;
    }

    public int getCommandId()
    {
        return commandId;
    }

    public void setCommandId(int commandId)
    {
        this.commandId = commandId;
    }

    public int getUid()
    {
        return uid;
    }

    public void setUid(int uid)
    {
        this.uid = uid;
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
    
    @Override
    public boolean equals (Object object) 
    {
        boolean result = false;
        
        if (object == null || object.getClass() != getClass()) 
        {
            result = false;
        } 
        else 
        {
            C2Msg msg = (C2Msg) object;
            
            if( this.clusterId  == msg.getClusterId()  && 
                this.scenarioId == msg.getScenarioId() && 
                this.uid        == msg.getUid()        &&
                this.commandId  == msg.getCommandId() )
            {
                result = true;
            }
        }
        
        return result;
    }
}