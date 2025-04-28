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

import java.io.File;
import java.util.ArrayList;

import com.draper.application.AppConfig;
import com.draper.services.c2.C2CommandEnum;
import com.draper.services.c2.C2Msg;
import com.draper.services.c2.C2Services;
import com.draper.services.corpus.CorpusServices;
import com.draper.services.database.ClusterBean;
import com.draper.services.database.DatabaseService;
import com.draper.services.database.ScenarioBean;
import com.draper.services.database.VMFBean;
import com.draper.services.performance.PerformanceServices;
import com.draper.utilities.Logger;
import com.draper.utilities.SystemState;
import com.google.gson.Gson;

/*******************************************************************
 * Provides Extension Services
 */
public class RegistrationServices
{
	private static final 	RegistrationServices instance 		= new RegistrationServices();

	/****************************************************************************************
	 * Instance pattern for singleton
	 *
	 */
 	static public RegistrationServices Instance()
	{		
		return instance;
	}
		
    /****************************************************************************************
     * Initialize the class.
     *
     */ 
 	public synchronized String HandleRegistration(String msg) throws Exception
    {
        RegistrationMsg           regMsg      = new Gson().fromJson( msg, RegistrationMsg.class);               
        RegistrationResponseMsg   regResp     = new RegistrationResponseMsg();          
        VMFBean                   vmfEntry    = new VMFBean();
        
        if( regMsg.getUid() != AppConfig.invalidId )
        {
            Logger.println( this, "Prior VMFID:" + regMsg.getUid() + " Being Upgraded" );
            
            VMFBean vmf  = DatabaseService.Instance().getVMF(regMsg.getUid());                
              
            // When this flag is set the VMF has completed what it was assigned to do
            // as opposed to receiving a STOP command. We decrease the capacity so 
            // that it is not retasked over and over
            if( regMsg.getTaskingComplete() == 1 )
            {
                ScenarioBean sb = DatabaseService.Instance().getScenario(vmf.getScenarioId());
                
                sb.setCapacity(sb.getCapacity()-1);
                DatabaseService.Instance().updateScenario(sb); 
            }
                           
            vmf.setStatus(StatusType.UNREGISTER.Id());
            DatabaseService.Instance().updateVMF(vmf);    
            
            PerformanceServices.Instance().setRegisteredFuzzers( PerformanceServices.Instance().getRegisteredFuzzers()-1);            
         }
        

        // Store VMF in the database
        vmfEntry.setPid(regMsg.getPid());
        vmfEntry.setHost(regMsg.getHost());        
        vmfEntry.setName(regMsg.getName());
        vmfEntry.setStatus(StatusType.IDLE.Id() );
        
        // Create the VMF in the Database
        DatabaseService.Instance().addVMF(vmfEntry);
        
        // Set Response Information       
        regResp.setPid(vmfEntry.getPid());
        regResp.setHost(vmfEntry.getHost());
        regResp.setUid(vmfEntry.getUid());
        regResp.setStatus(vmfEntry.getStatus());
        
        String myJSON = new Gson().toJson(regResp);
        
        PerformanceServices.Instance().setRegisteredFuzzers(PerformanceServices.Instance().getRegisteredFuzzers()+1);
        
        return myJSON;
    }
 
    /****************************************************************************************
     * Provide Tasking to a Registered VMF. This will assign the VMF to an available scenario
     * under a cluster and provide the list of initial seeds the scenario is setup to provide
     * 
     */ 
    public synchronized String HandleTasking(String uid) throws Exception
    {
        TaskingMsg   tasking        = new TaskingMsg();          
        VMFBean      theVMF         = DatabaseService.Instance().getVMF(Integer.valueOf(uid));
       
        // Set Status from Database. This is a placeholder unless we reassign the VMF
        /// In which case it will get a new Status
        tasking.setStatus(theVMF.getStatus());
        
        // Get list of Clusters and find one that is Ready then find a Scenario under it that has capacity
        ArrayList<ClusterBean> clusters = (ArrayList<ClusterBean>)DatabaseService.Instance().getClusters();
        
        for( ClusterBean cluster : clusters )
        {
            ArrayList<ScenarioBean> scenarios      = (ArrayList<ScenarioBean>)DatabaseService.Instance().getScenarios(cluster.getId());
            ScenarioBean            taskedScenario = null;
            
            for( ScenarioBean scenario : scenarios )
            {
                int vmfCount =  DatabaseService.Instance().getVMFCount(scenario.getId(), StatusType.UNREGISTER.Id());
                
                if( vmfCount < scenario.getCapacity() )
                {                    
                    taskedScenario = scenario;
                    break;
                }
            }
          
            if( taskedScenario != null)
            {            
                // Get the Latest Scenario and Cluster form the System
                theVMF.setClusterId(cluster.getId());
                theVMF.setScenarioId(taskedScenario.getId());
                theVMF.setStatus(StatusType.TASKED.Id() );
                
                DatabaseService.Instance().updateVMF(theVMF);   

                File     vmfConfig   = new File(CorpusServices.Instance().getScenarioConfigPath(theVMF.getClusterId(),theVMF.getScenarioId()));
                String[] vmfConfigs  = vmfConfig.list();

                // Return Assigned Tasking and configuration files
                tasking.setClusterId(theVMF.getClusterId());              
                tasking.setScenarioId(theVMF.getScenarioId());
                tasking.setStatus(theVMF.getStatus());
                tasking.setFiles(vmfConfigs); 
                
                break;
             }
        }      
                         
        String myJSON = new Gson().toJson(tasking);
             
        return myJSON;
    }
    
    
    /****************************************************************************************
    *   Handle the VMF transitions
    */ 
    public synchronized String HandleRegistrationStatus(String msg) throws Exception
    {
        RegistrationStatusMsg regStatusMsg = new Gson().fromJson( msg, RegistrationStatusMsg.class);               

        // Find the VMF and update the Scenario if necessary
        
        VMFBean      theVMF = DatabaseService.Instance().getVMF(regStatusMsg.getUid());
        ScenarioBean sb     = DatabaseService.Instance().getScenario(theVMF.getScenarioId());
       
        //Update the Scenario
        if( sb != null )
        {      
            if(regStatusMsg.getStatus() == StatusType.FAILED.Id() )
            {   
                // Stop the Scenario. Mark it as ERROR
                C2Msg  c2Msg  = new C2Msg();                   
                c2Msg.setClusterId( theVMF.getClusterId() );
                c2Msg.setScenarioId(theVMF.getScenarioId());
                c2Msg.setUid(0);
                c2Msg.setCommandId(C2CommandEnum.STOP.Id()); 
                C2Services.Instance().BroadcastMessage(c2Msg);
                
                sb.setCapacity(0);
                sb.setState(SystemState.ERROR.toString());            
                Logger.println(this, "Scenario:" + sb.getName() + " In ERROR from VMF: " + theVMF.getUid());
            }
            else if(regStatusMsg.getStatus() == StatusType.PAUSED.Id() )
            {
                Logger.println(this, "Scenario:" + sb.getName() + " VMF PAUSED: " + theVMF.getUid());
            }
            else if(regStatusMsg.getStatus() == StatusType.RUNNING.Id() )
            {
                // Do not count Paused we have already seen this VMF
                if( theVMF.getStatus() != StatusType.PAUSED.Id()  )
                {
                    sb.setFuzzerCount(sb.getFuzzerCount()+1);
                }
                
                sb.setState(SystemState.FUZZING.toString());              
                Logger.println(this, "Scenario now Fuzzing VMF: " + theVMF.getUid());
        
            }
            else if(regStatusMsg.getStatus() == StatusType.IDLE.Id() )
            {
                sb.setFuzzerCount(sb.getFuzzerCount()-1); 
                Logger.println(this, "Scenario:" + sb.getName() + " Reducing count IDLE VMF: " + theVMF.getUid());
            }
             
            // Update the Status of the Scenario
            
            if(sb.getFuzzerCount() == 0)
            {
                // Error state on scenario must be cleared manually
                if( !sb.getState().equalsIgnoreCase(SystemState.READY.toString()) &&
                    !sb.getState().equalsIgnoreCase(SystemState.ERROR.toString()) )
                {
                    sb.setState(SystemState.READY.toString());  
                }
            }
            else if( (sb.getFuzzerCount() <= sb.getCapacity()) && sb.getState().equalsIgnoreCase(SystemState.PENDING.toString()))
            {
                sb.setState(SystemState.FUZZING.toString());                                      
            }

            DatabaseService.Instance().updateScenario(sb);              
        }
                   
        // VMF is leaving the system. Remove it form Scenario and from the overall counts
        if(regStatusMsg.getStatus() == StatusType.UNREGISTER.Id() )
        {
            Logger.println(this, "Unregister VMF: " + theVMF.getUid());
                 
            if( sb != null )
            {
                sb.setFuzzerCount(sb.getFuzzerCount()-1); 
                DatabaseService.Instance().updateScenario(sb);    
                
                Logger.println(this, "Scenario VMF Count Reduced To: " + sb.getFuzzerCount());                         
            }
            
            PerformanceServices.Instance().setRegisteredFuzzers(PerformanceServices.Instance().getRegisteredFuzzers()-1);
        }               
                             
        // Update VMF       
        theVMF.setStatus(regStatusMsg.getStatus());
        theVMF.setReason(regStatusMsg.getReason());       
        DatabaseService.Instance().updateVMF(theVMF);               
         
        Logger.println("Handled RegistrationSStatusMsg:" + msg);
        
        return "{status:success}";
    }   
}