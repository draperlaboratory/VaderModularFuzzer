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
package com.draper.poller;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import com.draper.utilities.Logger;

/*************************************************************************************************
 * This is the top-level executive (main thread) for the poll system.
 * It looks for new polls in the PollInfo table and kicks off
 * appropriate processing tasks as necessary.  It utilizes a thread pool
 * to process all worker tasks concurrently.
 */
public class PollManager
{
    private 			 int               			maxPollerThreads;
    private 			 int               			startDelay;
    private 			 List<PollerThread>  	    pollerThreads;
    private 			 ScheduledExecutorService   pollExecutor;
	private static final PollManager 				instance 				= new PollManager();

	/*************************************************************************************************
     * 	Instance Bridge
     */
	static public PollManager Instance()
	{		
		return instance;
	}
	
	/*************************************************************************************************
     * 	Init the Poll Manager with configured number of threads 
     */
	public boolean Init(int numberofThreads, int startDelay)
	{		
        this.maxPollerThreads 	= numberofThreads;
        this.pollerThreads	 	= new ArrayList<PollerThread>();
        this.startDelay			= startDelay;
        
        for (int i = 0; i < maxPollerThreads; i++)
        {
        	pollerThreads.add(new PollerThread(i));
        }     
        
        // Create the thread pools.
        this.pollExecutor 	= Executors.newScheduledThreadPool(pollerThreads.size());
        
		return true;
	}
    
	/*************************************************************************************************
     * Shutdown the pollers
     */
    public void Stop() throws Exception
    {
        for( PollerThread pollerThread : pollerThreads )
        {   
            pollerThread.Stop();
        }      
        
        pollExecutor.shutdownNow();
    }
 
	/*************************************************************************************************
     * Assigns an available worker to process the poll.  
     * The first inactive worker found is used,
     * and it is run on a thread in the thread pool.
     * If no workers are available, then the poll is not processed.
     */
	public void InstallPoller(PollInterface poller, long period, TimeUnit unit)
    {   
    	try
    	{
	        // Find the first available worker and kick off the job.
	    	
	        for( PollerThread pollerThread : pollerThreads )
	        {   
	            if( false == pollerThread.isActive() )
	            {	                           	
	                Future<PollerThread> future = (Future<PollerThread>)pollExecutor.scheduleAtFixedRate(pollerThread, startDelay, period, unit); 
	                
	                pollerThread.Start(future, poller, Calendar.getInstance());
	                
	                break;
	            }
	        }
    	}
        catch(Exception ex)
        {
        	Logger.println("InstallPoller: " + ex);
        }    
    }
	
	 /*************************************************************************************************
     * Return a list of Active Poll Threads
     */
    public List<PollerThread> getActivePolls()
    { 
        List<PollerThread> activePolls = new ArrayList<PollerThread>(maxPollerThreads);
        
        try
        {
            // Find the first available worker and kick off the job.
            
            for( PollerThread theAbs : pollerThreads )
            {   
                if( true == theAbs.isActive() )
                {
                    activePolls.add(theAbs);
                }
            }
        }
        catch(Exception ex)
        {
            Logger.println(this, "GetActivePolls: " + ex);
        }   
        
        return activePolls;
    }
}
