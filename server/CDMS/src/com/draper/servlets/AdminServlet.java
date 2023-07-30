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
package com.draper.servlets;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.Part;

import com.draper.application.AppConfig;
import com.draper.services.c2.C2CommandEnum;
import com.draper.services.c2.C2Msg;
import com.draper.services.c2.C2Services;
import com.draper.services.campaign.CampaignService;
import com.draper.services.corpus.CorpusServices;
import com.draper.services.corpus.FileMsg;
import com.draper.services.database.ClusterBean;
import com.draper.services.database.DatabaseService;
import com.draper.services.database.ScenarioBean;
import com.draper.services.database.VMFBean;
import com.draper.services.performance.PerformanceServices;
import com.draper.services.performance.PerformanceView;
import com.draper.services.registration.StatusType;
import com.draper.utilities.Logger;
import com.draper.utilities.SystemEvent;
import com.draper.utilities.SystemState;
import com.draper.utilities.UiUtil;
import com.draper.utilities.UrlUtil;
import com.google.gson.Gson;

public class AdminServlet extends ControllerServlet
{
    private static final long serialVersionUID = 2L;
    
    /*************************************************************************************************
    * 
    */ 
    protected void processRequest(HttpServletRequest request, HttpServletResponse response) throws Exception
    {
        String[]    resourcePath = UrlUtil.getRestPath(request);
                
        //--------------------------------------------------------------------------------
        // Produce Information that is Used to Monitor the operational system performance.
        //--------------------------------------------------------------------------------

        if (resourcePath[0].equals("Performance"))
        {            
            String              ClusterId       = UiUtil.notNull(request.getParameter("ClusterId"));
            String              myJSON          = "{}";
            PerformanceView     pv              = null;

            try
            {
                pv      = PerformanceServices.Instance().GetPerformace( Integer.parseInt(ClusterId));            
                myJSON  = new Gson().toJson(pv);
            }
            catch( Exception e)
            {
                Logger.println(this, "Issue getting Perfomance");
            }
            
            response.setContentType("application/json");
            response.setCharacterEncoding("UTF-8");
            PrintWriter out = response.getWriter();
            out.println(myJSON);
            out.close();  
        }

        //--------------------------------------------------------------------------------
        // Show the current Log File to the User from the Server
        //--------------------------------------------------------------------------------
        if (resourcePath[0].equals("Log"))
        {
            Logger.println(this, "Requesting Latest Log");

            InputStream             is          = new FileInputStream(Logger.getLogFileName());
            InputStreamReader       isr         = new InputStreamReader(is);
            BufferedReader          reader      = new BufferedReader(isr);
            PrintWriter             writer      = response.getWriter();
            String text;

            response.setContentType("text/html");
            response.setCharacterEncoding("UTF-8");

            while( (text = reader.readLine()) != null)
            {
                writer.println(text);
            }
            
            writer.close();
            reader.close();
            isr.close(); 
            is.close();
            
            SystemEvent.add(request.getRequestURL().toString() + UrlUtil.getParameters(request));
        }
        
        //--------------------------------------------------------------------------------
        // Information on the Web Service
        //--------------------------------------------------------------------------------
        if (resourcePath[0].equals("Info"))
        {
            Logger.println(this, "Requesting Info");

            PrintWriter writer  = response.getWriter();

            response.setContentType("text/html");
            response.setCharacterEncoding("UTF-8");

            // Print the information we will use to initialize the system
            writer.println("Server Id  : " + AppConfig.serverIdentificationInfo);
            writer.println("WebService : " + AppConfig.webServiceIdentificationInfo);
            writer.println("Log        : " + Logger.getLogFileName());
            writer.println("Storage    : " + AppConfig.storagePath);
            writer.println("WebRoot    : " + AppConfig.webservicePath);
            writer.println("Use Stdout : " + Logger.getStdoutEcho());
            
            // Write the Event Log
            
            writer.println();
            writer.println("<<<<<<<   Event Log   >>>>>>>>");
            writer.println();
            
            ArrayList<SystemEvent> events = SystemEvent.getEvents();
            
            for(SystemEvent e : events )
            {
                writer.println( e.getTime() + "," + e.getDescription());  
            }

            writer.close();
            
            SystemEvent.add(request.getRequestURL().toString() + UrlUtil.getParameters(request));
        }
                

        //--------------------------------------------------------------------------------
        //
        //  Pause all fuzzing Scenarios in the Cluster
        //--------------------------------------------------------------------------------
        if( resourcePath[0].equals("DeleteScenario") )
        {    
            String  ScenarioId   = UiUtil.notNull(request.getParameter("ScenarioId"));
            
            Logger.println( this, "Delete Request for Scenario:" + ScenarioId);
            
            ScenarioBean sb = DatabaseService.Instance().getScenario(Integer.parseInt(ScenarioId));
            
            if( (sb.getCapacity() == 0) && (sb.getFuzzerCount() == 0) )
            {
                if( sb.getState().equals(SystemState.READY.toString()) || sb.getState().equals(SystemState.ERROR.toString()) )
                {
                    BroadcastC2Message( C2CommandEnum.STOP.Id(), sb.getClusterId(),sb.getId(), 0 );
                    
                    DatabaseService.Instance().deleteScenario(sb.getId());
                }                      
            }
            // Respond to the Get                
            response.setContentType("application/json");
            response.setCharacterEncoding("UTF-8");
            PrintWriter out = response.getWriter();
            out.println("{}");
            out.close();  
            
            SystemEvent.add(request.getRequestURL().toString() + UrlUtil.getParameters(request));

        }
        
        //--------------------------------------------------------------------------------
        //
        //  Pause all fuzzing Scenarios in the Cluster
        //--------------------------------------------------------------------------------
        if( resourcePath[0].equals("MinimizeCorpus") )
        {    
            String ScenarioId   = UiUtil.notNull(request.getParameter("ScenarioId"));
            int    scenarioId  = ScenarioId.isEmpty()  ? 0 : Integer.parseInt(ScenarioId);

            ScenarioBean sb = DatabaseService.Instance().getScenario(scenarioId);
            
            Logger.println("User Selected to Enable Minimize on the Scenario:" + sb.getName() );
            
            CampaignService.Instance().modifyScenarioCapacity(sb, 1);

            // Respond to the Get                
            response.setContentType("text/plain");
            response.setCharacterEncoding("UTF-8");
            PrintWriter out = response.getWriter();
            out.println("Broadcasted MinimizeCorpus Msg");
            out.close(); 
            
            SystemEvent.add(request.getRequestURL().toString() + UrlUtil.getParameters(request));
        }

        //--------------------------------------------------------------------------------
        //
        //  Stop the Cluster which will restart all VMF's runninng back to their
        //  Tasking request.
        //
        //--------------------------------------------------------------------------------
        if( resourcePath[0].equals("StopCluster") )
        {    
            String                  ClusterId   = UiUtil.notNull(request.getParameter("ClusterId"));
            int                     clusterId   = ClusterId.isEmpty()  ? 0 : Integer.parseInt(ClusterId);    
            ClusterBean             cb          = DatabaseService.Instance().getCluster(Integer.parseInt(ClusterId));           
            ArrayList<ScenarioBean> sbl         = (ArrayList<ScenarioBean>)DatabaseService.Instance().getScenarios(clusterId);
            boolean                 stopIssued  = false;
            
            for( ScenarioBean sb : sbl )
            {
                if( sb.getFuzzerCount() > 0 )
                {
                    sb.setCapacity(0);
                    sb.setState(SystemState.PENDING.toString());
                    DatabaseService.Instance().updateScenario(sb);
                    
                    BroadcastC2Message( C2CommandEnum.STOP.Id(), clusterId, sb.getId(), 0 );
                    
                    stopIssued = true;
                }
            }
            
            // No Stop issued means nothing is happening so set cluster to ready
            
            if( false == stopIssued)
            {
                cb.setState(SystemState.READY.toString());
                DatabaseService.Instance().updateCluster(cb);
            }
            
            // Respond to the Get                
            response.setContentType("text/plain");
            response.setCharacterEncoding("UTF-8");
            PrintWriter out = response.getWriter();
            out.println("Broadcasted StopCluster Msg");
            out.close();  
            
            SystemEvent.add(request.getRequestURL().toString() + UrlUtil.getParameters(request));
        }

        //--------------------------------------------------------------------------------
        //
        // Halt the system
        //--------------------------------------------------------------------------------
        if( resourcePath[0].equals("Shutdown") )
        {    
            BroadcastC2Message( C2CommandEnum.SHUTDOWN.Id(), 0, 0, 0 );

            ArrayList<ClusterBean> cbl = (ArrayList<ClusterBean>)DatabaseService.Instance().getClusters();
            
            for( ClusterBean cb : cbl )
            {
                ArrayList<ScenarioBean> sbl = (ArrayList<ScenarioBean>)DatabaseService.Instance().getScenarios(cb.getId());
                
                for( ScenarioBean sb : sbl )
                {
                    sb.setCapacity(0);
                    sb.setFuzzerCount(0);
                    sb.setState(SystemState.READY.toString());
                    DatabaseService.Instance().updateScenario(sb);      
                    PerformanceServices.Instance().setRegisteredFuzzers(0);
              
                    ArrayList<VMFBean> vmfs = (ArrayList<VMFBean>)CampaignService.Instance().getActiveVMFs(sb.getId());
                    
                    for( VMFBean vmf : vmfs )
                    {
                        vmf.setStatus(StatusType.UNREGISTER.Id());
                        vmf.setReason("UI Shutdown");
                        DatabaseService.Instance().updateVMF(vmf);                         
                        
                        BroadcastC2Message( C2CommandEnum.STOP.Id(), cb.getId(), sb.getId(), vmf.getUid());
                    }
                }
            
                cb.setState(SystemState.READY.toString());
                DatabaseService.Instance().updateCluster(cb);                         
            }

            // Respond to the Get                
            response.setContentType("text/plain");
            response.setCharacterEncoding("UTF-8");
            PrintWriter out = response.getWriter();
            out.println("Broadcasted Shutdown Msg");
            out.close();  
            
            SystemEvent.add(request.getRequestURL().toString() + UrlUtil.getParameters(request));
        }
        
        //--------------------------------------------------------------------------------
        // List of Configuration files Loaded into the clusters Disk storage
        //--------------------------------------------------------------------------------
       
        if( resourcePath[0].equals("listcluster") )
        {        
            int                 clusterId    = Integer.parseInt(resourcePath[1]);            
            File                storagePath  = new File(CorpusServices.Instance().getClusterPath(clusterId));
            ArrayList<FileMsg>  files        = new ArrayList<FileMsg>();           
            Path                sourcePath   = Paths.get(storagePath.getCanonicalPath());

            try
            {
                Files.walk(sourcePath).forEach(source -> 
                { 
                    if( !Files.isDirectory(source) )
                    {
                        String fileType     = "NA";
                        long   size         = 0;
                        String lastModified = "NA";
                        
                        try  { fileType = Files.probeContentType(source); }
                        catch(IOException ioException){}   
                        
                        try  { size = Files.size(source); }
                        catch(IOException ioException){}                        
    
                        try  { lastModified = Files.getAttribute(source, "lastModifiedTime").toString(); }
                        catch(IOException ioException){}                        
     
                        FileMsg fileItem = new FileMsg(source.getFileName().toString(),size,fileType, lastModified);
                  
                        files.add( fileItem );                                       
                    }
                });            
            }
            catch(Exception e)
            {
                Logger.println(this, "Error getting Files in Cluster:" + e.getMessage());
            }
                         
            //Return the List to the Browser in Json Format
             
            String myJSON = new Gson().toJson(files);

            response.setContentType("application/json");
            response.setCharacterEncoding("UTF-8");
            PrintWriter out = response.getWriter();
            out.println(myJSON);
            out.close();  
            
            SystemEvent.add(request.getRequestURL().toString() + UrlUtil.getParameters(request));
        }
            
         //--------------------------------------------------------------------------------
        // 
        //--------------------------------------------------------------------------------
       
        if( resourcePath[0].equals("upload") )
        {        
            int    clusterId       = Integer.parseInt(resourcePath[1]);            
            File   destPath        = new File(CorpusServices.Instance().getClusterPath(clusterId));
            File   tempPath        = new File(getServletContext().getRealPath("") + File.separator + "cluster" + clusterId);
            
            if (!tempPath.exists())
            {
                tempPath.mkdirs();
            }     

            for(Part p : request.getParts())
            {             
                Logger.println( "Saving Cluster File: " +  tempPath + File.separator + extractFileName(p) );
                
                p.write(tempPath +File.separator + extractFileName(p) );
            }
             
            //Copying FIles to Cluster area
            
            Path sourceTemppath   = Paths.get(tempPath.getCanonicalPath());
            Path destinationPath  = Paths.get(destPath.getCanonicalPath());     

            Files.walk(sourceTemppath).forEach(source -> UiUtil.CopyFiles(source, destinationPath.resolve(sourceTemppath.relativize(source)))); 

            // Delete the temp files and directory
            
            Files.walk(sourceTemppath).forEach(source -> UiUtil.DeleteFile(source)); 
            tempPath.delete();
            
            // Respond to the Get                
            response.setContentType("application/json");
            response.setCharacterEncoding("UTF-8");
            PrintWriter out = response.getWriter();
            out.println("{\"status\": \"Files are uploaded\"}");
            out.close();    
            
            SystemEvent.add(request.getRequestURL().toString() + UrlUtil.getParameters(request));
        }
    }

 
     /*************************************************************************************************
     * 
     */
    private String extractFileName(Part part) 
    {
        String      contentDisp = part.getHeader("content-disposition");
        String[]    items       = contentDisp.split(";");
        
        for (String s : items) 
        {
            if (s.trim().startsWith("filename")) 
            {
                return s.substring(s.indexOf("=") + 2, s.length()-1);
            }
        }
        return "";
    }
  
    /*************************************************************************************************
     * 
     */
    private void BroadcastC2Message(int commandId, int clusterId, int scenarioId, int vmfid )
    {    
        C2Msg msg = new C2Msg();
        
        msg.setCommandId(commandId);
        msg.setClusterId(clusterId);
        msg.setScenarioId(scenarioId);
        msg.setUid(vmfid);
            
        Logger.println(this, "Broadcasting C2 Msg: " + commandId);
        
        C2Services.Instance().BroadcastMessage(msg);                
    }


}