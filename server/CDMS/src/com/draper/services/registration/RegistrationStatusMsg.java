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

public class RegistrationStatusMsg
{
    private int                             uid;
    private int                  	        status;
    private String                          reason;

  
    public RegistrationStatusMsg()
    {
        this.uid             	= 0;
        this.status             = StatusType.IDLE.Id();
        this.reason             = "";
    }
    
    public RegistrationStatusMsg(int uid, int status, String reason)
    {
        this.uid                = uid;
        this.status             = status;
        this.reason             = reason;
    }

	public String getReason() 
	{
		return reason;
	}

	public void setReason(String reason) 
	{
		this.reason = reason;
	}

	public int getStatus() 
	{
		return this.status;
	}

	public void setStatus(int status) 
	{
		this.status = status;
	}

	public int getUid() 
	{
		return uid;
	}

	public void setUid(int uid) 
	{
		this.uid = uid;
	}
}
