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
package com.draper.servlets;

import java.io.File;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.draper.application.AppConfig;
import com.draper.services.campaign.CampaignService;
import com.draper.services.campaign.ClusterListView;
import com.draper.services.campaign.ScenarioUI;
import com.draper.services.campaign.VmfUI;
import com.draper.services.corpus.CorpusServices;
import com.draper.services.database.ClusterBean;
import com.draper.services.database.DatabaseService;
import com.draper.services.database.ScenarioBean;
import com.draper.services.database.VMFBean;
import com.draper.services.performance.KPIMsg;
import com.draper.utilities.KVPair;
import com.draper.utilities.Logger;
import com.draper.utilities.SystemEvent;
import com.draper.utilities.SystemState;
import com.draper.utilities.UiUtil;
import com.draper.utilities.UrlUtil;
import com.google.gson.Gson;

/*************************************************************************************************
 *  This service will access the Campaign information in the database 
 *  
 */
public class CampaignServlet extends ControllerServlet 
{
    /*************************************************************************************************
	 * 
	 */
	private static final    long serialVersionUID = 1L;

    /*************************************************************************************************
	 * 
	 */
	protected void processRequest(HttpServletRequest request, HttpServletResponse response) throws Exception
	{		
        String[]    resourcePath = UrlUtil.getRestPath(request);
        
        //---------------------------------------------------------------------------------------------
        // Create structure

        if( resourcePath[0].equals("create") && resourcePath[1].equals("cluster") )
        {                             
           String Title         = UiUtil.notNull(request.getParameter("Title"));
           String Description   = UiUtil.notNull(request.getParameter("Description"));
            
           ClusterBean cluster = new ClusterBean();
           cluster.setName(Title);
           cluster.setDescription(Description);               
           cluster.setState(SystemState.READY.toString());  
           cluster.setEdit(UiUtil.fmtDate(new Date(),UiUtil.TIMESTAMP_FORMAT));

           
           DatabaseService.Instance().addCluster(cluster);
           
           CorpusServices.Instance().CreateClusterStorage(cluster.getId(), AppConfig.invalidId );
            
           String myJSON = new Gson().toJson(cluster);
                      
           response.setContentType("application/json");
           response.setCharacterEncoding("UTF-8");
           PrintWriter out = response.getWriter();
           out.println(myJSON);
           out.close();     
           
           return;
       } 
          
        //---------------------------------------------------------------------------------------------
        // Create structure

        if( resourcePath[0].equals("create") && resourcePath[1].equals("scenario") )
        {                             
           String Title         = UiUtil.notNull(request.getParameter("Title"));
           String ClusterId     = UiUtil.notNull(request.getParameter("ClusterId"));
           String Capacity      = UiUtil.notNull(request.getParameter("Capacity"), "0");
           String Configs       = UiUtil.notNull(request.getParameter("Configs"));
           String Seeds         = UiUtil.notNull(request.getParameter("Seeds"));
           String Type          = UiUtil.notNull(request.getParameter("Type"));
                     
           ClusterBean cluster  = DatabaseService.Instance().getCluster(Integer.parseInt(ClusterId));        
           
           ScenarioBean scenario = new ScenarioBean();
           scenario.setName(Title);
           scenario.setType(Type);           
           scenario.setState(SystemState.READY.toString());  
           scenario.setClusterId(cluster.getId());  
           scenario.setCapacity(Integer.parseInt(Capacity));
           scenario.setFuzzerCount(0);
           DatabaseService.Instance().addScenario(scenario);
          
           CorpusServices.Instance().CreateScenarioStorage(cluster.getId(), scenario.getId());
           
           File clusterPath             = new File(CorpusServices.Instance().getClusterPath(cluster.getId()));
           File scenarioSeedPath        = new File(CorpusServices.Instance().getScenarioSeedPath(cluster.getId(),scenario.getId()));
           File scenarioConfigPath      = new File(CorpusServices.Instance().getScenarioConfigPath(cluster.getId(),scenario.getId()));
           Path sourcePath              = Paths.get(clusterPath.getCanonicalPath());
           Path destinationConfigPath   = Paths.get(scenarioConfigPath.getCanonicalPath());
           Path destinationSeedPath     = Paths.get(scenarioSeedPath.getCanonicalPath());
           String[] configList          = Configs.split(",");
           String[] seedList            = Seeds.split(",");

           Files.walk(sourcePath).filter(p -> UiUtil.stringContainsItemFromList(p.getFileName().toString(),configList)).forEach(source -> UiUtil.CopyFiles(source, destinationConfigPath.resolve(sourcePath.relativize(source)))); 

           Files.walk(sourcePath).filter(p -> UiUtil.stringContainsItemFromList(p.getFileName().toString(),seedList)).forEach(source -> UiUtil.CopyFiles(source, destinationSeedPath.resolve(sourcePath.relativize(source)))); 
           
           String myJSON = new Gson().toJson(scenario);
           
           response.setContentType("application/json");
           response.setCharacterEncoding("UTF-8");
           PrintWriter out = response.getWriter();
           out.println(myJSON);
           out.close();     
           
           return;
       } 
          
        //---------------------------------------------------------------------------------------------
        // Update the clusters information including capacity of the scenarios
        if( resourcePath[0].equals("update") && resourcePath[1].equals("cluster") )      
        {  
            String         ClusterId     = UiUtil.notNull(request.getParameter("ClusterId"));
            String         CapacityList  = UiUtil.notNull(request.getParameter("CapacityList"));
            String         CapacityKV[]  = CapacityList.split(",");
            
            Logger.println( this, " ClusterId:"+ ClusterId +  " CapList:" + CapacityList );
               
            for( int ScenarioKeyIndex = 0; ScenarioKeyIndex < CapacityKV.length; ScenarioKeyIndex +=2 ) 
            {  
                ScenarioBean  scenario    = CampaignService.Instance().getScenario(CapacityKV[ScenarioKeyIndex]); 
                int           newCapacity = Integer.parseInt(CapacityKV[ScenarioKeyIndex+1]);
                                
                CampaignService.Instance().modifyScenarioCapacity(scenario, newCapacity);                             
            }
             
            response.setContentType("application/json");
            response.setCharacterEncoding("UTF-8");
            PrintWriter out = response.getWriter();
            out.println("{}");
            out.close();     
            
            return;
        }
                        
        //---------------------------------------------------------------------------------------------
        // Get the list of clusters to display to the user
        
        if( resourcePath[0].equals("get") && resourcePath[1].equals("clusters") )
        {        	
            ArrayList<ClusterBean>      clusters = CampaignService.Instance().getClusters();
            ArrayList<ClusterListView>  clvLsit  = new ArrayList<ClusterListView>();
            
            for( ClusterBean cluster : clusters )
            {              
                ClusterListView clv             = new ClusterListView(cluster);                
                int             corpusSize      = DatabaseService.Instance().getTestCount(cluster.getId());
           
                clv.setCorpusSize(corpusSize);                  
                clvLsit.add(clv);
            }
            
            // Sort the Array based on Appointment Date in Overview
        
            Collections.sort(clvLsit);
      
            //Return the List to the Browser in Json Format
             
            String myJSON = new Gson().toJson(clvLsit);
 
            response.setContentType("application/json");
            response.setCharacterEncoding("UTF-8");
            PrintWriter out = response.getWriter();
            out.println(myJSON);
            out.close();     
            
            SystemEvent.add(request.getRequestURI() + UrlUtil.getParameters(request));
            
            return;
        }
            
        //---------------------------------------------------------------------------------------------
        // Get the list of scenarios for the cluster
        
        if( resourcePath[0].equals("get") && resourcePath[1].equals("scenarios"))
        {    
            String                  clusterId     = UiUtil.notNull(request.getParameter("clusterId"));
            ArrayList<ScenarioUI>   scenarioList  = new  ArrayList<ScenarioUI>();           
         	ArrayList<ScenarioBean> scenarios     = CampaignService.Instance().getScenarios(Integer.parseInt(clusterId));
 
         	 for( ScenarioBean sb : scenarios )
         	 {
         	     ScenarioUI                 scenarioui = new ScenarioUI();
         	     ArrayList<VMFBean>         vmfs       = CampaignService.Instance().getActiveVMFs(sb.getId());
                 KVPair                     kvp[]      = null;
                 KPIMsg                     kpimsg     = null;               
                 HashMap<String, Float>     Averages   = new HashMap<String, Float>();
                 
                 for( VMFBean vmf : vmfs)
         	     {
                     if(!vmf.getJson().equals("NA"))
                     {
             	         kpimsg  = new Gson().fromJson(vmf.getJson(),KPIMsg.class );        	        
              	         kvp     = kpimsg.getMetrics();
              	         
              	         // Walk thru the metrics adding them to the running count
              	                
              	         for( int i = 0; i < kvp.length; i++ )
              	         {
              	             if( false == Averages.containsKey(kvp[i].getKey() ))
              	             {
              	                 Averages.put(kvp[i].getKey(), Float.parseFloat(kvp[i].getValue()));   	                  	                 
              	             }
              	             else
              	             {
              	                 float runningCount = Averages.get(kvp[i].getKey());         	                 
              	                 float value        = Float.parseFloat(kvp[i].getValue());
              	                 runningCount      += value;
              	               
              	                 Averages.put(kvp[i].getKey(), runningCount);       	               
              	             }
              	         }
                     }
           	     }
         	     
                 // Compute Averages for each Key  and add to List of Keys
                 
                 ArrayList<KVPair> kvpList = new ArrayList<KVPair>();

                 for (String key : Averages.keySet()) 
                 {
                     float   runningCount = Averages.get(key);
                     float   average      = runningCount / (float)vmfs.size();
                     KVPair  avgPair      = new KVPair(key, Float.toString(average) );
                     
                     kvpList.add(avgPair);
                 }

                 // Set Scenario information for Display
                 scenarioui.setId(sb.getId());                
                 scenarioui.setScenarioName(sb.getName());
                 scenarioui.setVMFLink(sb.getName(), sb.getId() );
         	     scenarioui.setType(UiUtil.notNull(sb.getType()));
                 scenarioui.setState(UiUtil.notNull(sb.getState()));
         	     scenarioui.setActiveFuzzers(sb.getFuzzerCount());
         	     scenarioui.setData(kvpList);
         	     scenarioui.setCapacity(sb.getCapacity());
         	    
         	     scenarioList.add(scenarioui);
         	 }
         	 
         	 // If there are no scenarios..just return a UI placeholder
         	 
         	 if( scenarioList.size() == 0)
         	 {
         	    scenarioList.add( new ScenarioUI());
         	 }
         	 
             //Return the List to the Browser in Json Format
             
             String myJSON = new Gson().toJson(scenarioList);
 
             response.setContentType("application/json");
             response.setCharacterEncoding("UTF-8");
             PrintWriter out = response.getWriter();
             out.println(myJSON);
             out.close();     
             
             return;
        }   

        //---------------------------------------------------------------------------------------------
        // Get the list of scenarios for the cluster. This is a lower leve lcall so that we can
        // Update the management UI with the capacities
        if( resourcePath[0].equals("get") && resourcePath[1].equals("scenarioBeans"))
        {    
            String                  clusterId     = UiUtil.notNull(request.getParameter("clusterId"));
            ArrayList<ScenarioBean> scenarios     = CampaignService.Instance().getScenarios(Integer.parseInt(clusterId));
            ArrayList<ScenarioUI>   scenarioList  = new  ArrayList<ScenarioUI>();           
            
            for( ScenarioBean sb : scenarios )
            {
                ScenarioUI  scenarioui = new ScenarioUI();
                
                scenarioui.setId(sb.getId());                
                scenarioui.setScenarioName(sb.getName());
                scenarioui.setType(UiUtil.notNull(sb.getType()));
                scenarioui.setState(UiUtil.notNull(sb.getState()));
                scenarioui.setActiveFuzzers(sb.getFuzzerCount());
                scenarioui.setCapacity(sb.getCapacity());
               
                String action = "<a href='#' onclick='deleteScenario(event,"+sb.getId()+ ",\"" + sb.getName()+"\");'><img class='logo' src='icons/delete.png' alt='Delete' width='15' height='15'></a>";
 
                scenarioui.setAction(action);
                scenarioList.add(scenarioui);
             }
            
            // Sort the Array based on Appointment Date in Overview
            
            Collections.sort(scenarioList);
            
            String myJSON = new Gson().toJson(scenarioList);

            response.setContentType("application/json");
            response.setCharacterEncoding("UTF-8");
            PrintWriter out = response.getWriter();
            out.println(myJSON);
            out.close();                
        }
        
        //---------------------------------------------------------------------------------------------
        // Get the list of scenarios for the cluster        
        if( resourcePath[0].equals("get") && resourcePath[1].equals("vmfs"))
        {    
             String                scenarioId = UiUtil.notNull(request.getParameter("ScenarioId"));
             ArrayList<VMFBean>    vmfs       = (ArrayList<VMFBean>)DatabaseService.Instance().getVMFs(Integer.parseInt(scenarioId));
             ArrayList<VmfUI>      vmfList    = new ArrayList<VmfUI>(vmfs.size());
         
             for( VMFBean vmf : vmfs)
             {
                VmfUI vmfui = new VmfUI(vmf);                 
                
                if( !vmf.getJson().equals("NA") )
                {                  
                    KPIMsg            kpimsg  = new Gson().fromJson(vmf.getJson(),KPIMsg.class );                   
                    KVPair            kvp[]   = kpimsg.getMetrics();
                    ArrayList<KVPair> kvpList = new ArrayList<KVPair>(kvp.length);
                
                    for( int i = 0; i < kvp.length; kvpList.add(kvp[i++]) );
                    
                    vmfui.setData(kvpList);
                }
                
                vmfList.add(vmfui);
             }
                         
             //Return the List to the Browser in Json Format
              
             String myJSON = new Gson().toJson(vmfList);

             response.setContentType("application/json");
             response.setCharacterEncoding("UTF-8");
             PrintWriter out = response.getWriter();
             out.println(myJSON);
             out.close();  
             
             
             return;
        }          
	}
}