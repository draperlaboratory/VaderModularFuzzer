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

import java.util.ArrayList;

import com.draper.services.c2.C2CommandEnum;
import com.draper.services.c2.C2Msg;
import com.draper.services.c2.C2Services;
import com.draper.services.database.ClusterBean;
import com.draper.services.database.DatabaseService;
import com.draper.services.database.ScenarioBean;
import com.draper.services.database.VMFBean;
import com.draper.services.registration.StatusType;
import com.draper.utilities.Logger;
import com.draper.utilities.SystemState;

//---------------------------------------------------------------------------------------------------------------
//
//
//---------------------------------------------------------------------------------------------------------------     
public final class CampaignService
{
    private static final    CampaignService     instance    = new CampaignService();

    
    /****************************************************************************************
     * Instance pattern for singleton
     *
     */
    static public CampaignService Instance()
    {       
        return instance;
    }
    
    /****************************************************************************************
    *
    */ 
    public ArrayList<ClusterBean> getRegisteredVMFs() throws Exception
    {
          ArrayList<ClusterBean> clusters  = (ArrayList<ClusterBean>)DatabaseService.Instance().getClusters();
       
          return clusters;       
    }

    /****************************************************************************************
    * Going to zero will stop the Scenario. Send a STOP command VMFs
    */ 
    public void adjustScenarioVMFCount() throws Exception
    {
    }
    
    /****************************************************************************************
    *
    */ 
    public void archiveScenario() throws Exception
    {
    }   
    
    /****************************************************************************************
    *
    */ 
    public ArrayList<ClusterBean> getClusters() throws Exception
    {
          ArrayList<ClusterBean> clusters  = (ArrayList<ClusterBean>)DatabaseService.Instance().getClusters();
       
          return clusters;       
    }
        
    /****************************************************************************************
    * 
    */ 
    public ArrayList<ScenarioBean> getScenarios(int clusterId) throws Exception
    {
          ArrayList<ScenarioBean> scenarios = (ArrayList<ScenarioBean>)DatabaseService.Instance().getScenarios(clusterId);
       
          return scenarios;       
    }
    
    /****************************************************************************************
    * 
    */ 
    public ScenarioBean getScenario(String scenarioId) throws Exception
    {
          ScenarioBean scenario = DatabaseService.Instance().getScenario(Integer.parseInt(scenarioId));
       
          return scenario;       
    }

    /****************************************************************************************
    *  Get all VMFS that are active on a scenario
    */ 
    public ArrayList<VMFBean> getActiveVMFs(int scenarioId ) throws Exception
    {
          ArrayList<VMFBean>  vmfs         = (ArrayList<VMFBean>)DatabaseService.Instance().getVMFs(scenarioId);
          ArrayList<VMFBean>  filteredList = new ArrayList<VMFBean>();
          
          for ( VMFBean vmf : vmfs)
          {
              if( vmf.getStatus() != StatusType.UNREGISTER.Id() )
              {
                  filteredList.add(vmf);
              }
          }
          return filteredList;       
    } 

    /****************************************************************************************
    *  Get all Scenarios that are of Fuzzer Type
    */ 
    public ArrayList<ScenarioBean> getFuzzingScenarios(int clusterId ) throws Exception
    {
          ArrayList<ScenarioBean>  scenarios    = (ArrayList<ScenarioBean>)DatabaseService.Instance().getScenarios(clusterId);
          ArrayList<ScenarioBean>  filteredList = new ArrayList<ScenarioBean>();
          
          for ( ScenarioBean scenario : scenarios)
          {
              if( scenario.getType().equalsIgnoreCase("Fuzzer") )
              {
                  filteredList.add(scenario);
              }
          }
          return filteredList;       
    }   
    
    /****************************************************************************************
     *  Get all Scenarios that are of Fuzzer Type
     */ 
     public void modifyScenarioCapacity(ScenarioBean scenario, int newCapacity ) throws Exception
     {
          
          if( scenario.getState().equalsIgnoreCase(SystemState.READY.toString()) || 
              scenario.getState().equalsIgnoreCase(SystemState.FUZZING.toString())  )
          {
                Logger.println(this, " Updating Scenario:" + scenario.getName() + " With new Capcity:" + newCapacity);
                
                // Remove any fuzzers from the Scenario to match capacity
                // Stopping a fuzzer will put it back to Idle and it wiil re-register
                
                if( scenario.getFuzzerCount() > newCapacity )
                {
                    ArrayList<VMFBean> vmfs = CampaignService.Instance().getActiveVMFs(scenario.getId());
                                     
                    for( int i = newCapacity, index = 0; i <  scenario.getFuzzerCount(); i++, index++ )
                    {
                        C2Msg c2Msg  = new C2Msg();                   
                        c2Msg.setClusterId( scenario.getClusterId() );
                        c2Msg.setScenarioId(scenario.getId());
                        c2Msg.setUid(vmfs.get(index).getUid());
                        c2Msg.setCommandId(C2CommandEnum.STOP.Id()); 
                        C2Services.Instance().BroadcastMessage(c2Msg);
                    }
                    
                    //Changes are being made
                    scenario.setState(SystemState.PENDING.toString());
                }                
                    
                // Update to new user selected capacity
                scenario.setCapacity(newCapacity);               
                DatabaseService.Instance().updateScenario(scenario);                            
          }       
     }
}