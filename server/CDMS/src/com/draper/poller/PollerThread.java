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
package com.draper.poller;
 
import java.sql.Timestamp;
import java.util.Calendar;
import java.util.Date;
import java.util.concurrent.Future;

import com.draper.utilities.Logger;


/*************************************************************************************************
 * A worker class for pollInfo classes.
 */
public  class PollerThread implements Runnable
{
    private     PollInterface				theImp;
	private 	long 						pollStartTime;    
	private		int							execCounter;
	private		int							id;
	private     Future<PollerThread> 		future;
	private 	boolean 					active;    
	private     Date                        date;
	 
	
	/*************************************************************************************************
     * Create a new pollInfo worker with its required resources
     */
    public PollerThread(int id)
    {
        this.active   			= false;
        this.id					= id;
        this.execCounter 		= 0;
        this.future  		    = null;
        this.theImp   			= null;
        this.pollStartTime 		= 0L;
        this.date               = new Date();
    }
    
        
	/*************************************************************************************************
     * @return Get the Id assigned to this poller
     */
    public int getId()
    {
        return this.id;
    }
     

    /*************************************************************************************************
     * @return the PollerInterface assigned to thit scheduling thread
     */
    public PollInterface getPoller()
    {
        return theImp;
    }


	/*************************************************************************************************
     * Returns whether or not this worker is currently  polling
     */
    public boolean isActive()
    {
        return active;
    }
    
    /*************************************************************************************************
     * Setup the thread with the information it uses during execution
     */
    public void Start(Future<PollerThread> future, PollInterface poller, Calendar instance)
    {
        this.future             = future;
        this.theImp             = poller;
        this.pollStartTime      = instance.getTimeInMillis();
        this.active             = true;        
    }
    	
    /*************************************************************************************************
     * Stop the execution of the thread.
     * Define the completed flag for the poll as a parameter.
     */
    public void Stop() throws Exception
    {
    	if( null != future)
    	{
    		Logger.println( this, "Stopping Poller" );
    		
    		future.cancel(true);    
    		
    		theImp.Stop();
    	} 
    	    	
    	// Mark as inactive so it can be used again.
    	
    	this.active = false;
    }
          

	/*************************************************************************************************
     * The run method of this worker. Build the class in the poll record
     * which is supplied by the poll creator and call it.   
     */
    public void run()
    {         
    	try
    	{   
     		theImp.Execute( this.execCounter, new Timestamp(date.getTime()) );   
    		
    		this.execCounter++;		
    		
    		return;
    	}
    	catch(Exception e)
    	{
    		Logger.println( this, e );
    	}

    	try
    	{
    	    this.Stop();
    	}
    	catch(Exception e)
    	{
            Logger.println( this, e );    	    
    	}
    }


}
