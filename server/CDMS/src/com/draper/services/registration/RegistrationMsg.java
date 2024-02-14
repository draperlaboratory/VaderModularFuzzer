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
package com.draper.services.registration;

public class RegistrationMsg
{
    private int                     uid;
    private int                     pid;
    private String                  host;   
    private String                  name;
    private int                     taskingComplete;
    
    public RegistrationMsg()
    {
        this.pid              = 0;
        this.uid              = 0;
        this.host             = "";
        this.name             = "";
        this.taskingComplete  = 0;
    }
    
    public RegistrationMsg(String name, String host, int pid)
    {
        this.pid              = pid;
        this.uid              = 0;
        this.host             = host;
        this.name             = name;
        this.taskingComplete  = 0;
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

	public String getName() 
	{
		return name;
	}

	public void setName(String name) 
	{
		this.name = name;
	}

    public int getUid()
    {
        return uid;
    }

    public void setUid(int uid)
    {
        this.uid = uid;
    }

    public int getTaskingComplete()
    {
        return taskingComplete;
    }

    public void setTaskingComplete(int taskingComplete)
    {
        this.taskingComplete = taskingComplete;
    }

}
