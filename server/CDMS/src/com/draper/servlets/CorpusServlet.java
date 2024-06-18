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
package com.draper.servlets;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Hashtable;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.draper.application.AppConfig;
import com.draper.services.c2.C2CommandEnum;
import com.draper.services.c2.C2Msg;
import com.draper.services.c2.C2Services;
import com.draper.services.campaign.CampaignService;
import com.draper.services.corpus.CorpusMsg;
import com.draper.services.corpus.CorpusServices;
import com.draper.services.corpus.TestCaseMsg;
import com.draper.services.corpus.TestCaseView;
import com.draper.services.database.ClusterBean;
import com.draper.services.database.CorpusBean;
import com.draper.services.database.CorpusToTestCaseBean;
import com.draper.services.database.DatabaseService;
import com.draper.services.database.ScenarioBean;
import com.draper.services.database.TestCaseBean;
import com.draper.utilities.Logger;
import com.draper.utilities.SystemEvent;
import com.draper.utilities.UiUtil;
import com.draper.utilities.UrlUtil;
import com.draper.utilities.ZipManager;
import com.google.gson.Gson;

/*************************************************************************************************
 */
public class CorpusServlet extends ControllerServlet
{
	private static final long    serialVersionUID = 4L;
	
	/*************************************************************************************************
    * 
    */
   	protected void processRequest(HttpServletRequest request, HttpServletResponse response) throws Exception
   	{
       String[]    resourcePath = UrlUtil.getRestPath(request);

       
       //--------------------------------------------------------------------------------
       // Pause all Fuzzing Scenarios in the Cluster
       //--------------------------------------------------------------------------------
       if (resourcePath[0].equals("pause"))
       {
           int                     clusterId   = Integer.parseInt(resourcePath[1]);                   
           ClusterBean             cb          = DatabaseService.Instance().getCluster(clusterId);          
           ArrayList<ScenarioBean> sbl         = CampaignService.Instance().getFuzzingScenarios(clusterId);
           
           for(ScenarioBean sb : sbl )
           {
               C2Msg  c2Msg  = new C2Msg();                   
               c2Msg.setClusterId( sb.getClusterId() );
               c2Msg.setScenarioId( sb.getId() );                           
               c2Msg.setUid(0);                                                      
               c2Msg.setCommandId(C2CommandEnum.PAUSE.Id()); 
               C2Services.Instance().BroadcastMessage(c2Msg);
               Logger.println(this, "Commangind a Pause on Cluster: " + cb.getName() + " Scenario: " + sb.getName());
           }
          
           // Respond to the Get                
           response.setContentType("text/plain");
           response.setCharacterEncoding("UTF-8");
           PrintWriter out = response.getWriter();
           out.println("Broadcasted Pause Cluster Msg to Fuzzer Scenarios");
           out.close(); 
           
           SystemEvent.add(request.getRequestURL().toString() + UrlUtil.getParameters(request));
       }
 
       //--------------------------------------------------------------------------------
       // Get a File from Scenario Storage. This is a generic fetch of a file.
       // TODO: Set a return Mimetype to tell the client what type of file this is.
       //--------------------------------------------------------------------------------
       if (resourcePath[0].equals("file"))
       {      
           String          fileName        = CorpusServices.Instance().getBasePath() + File.separator + resourcePath[1];
           File            downloadFile    = new File(fileName);
           FileInputStream inStream        = new FileInputStream(downloadFile);

           Logger.println(this, "Client Requesting File Download:" + downloadFile);
           
           response.setContentType("application/octet-stream");
           response.setContentLength((int)downloadFile.length());
                   
           OutputStream outStream = response.getOutputStream();
            
           byte[] buffer = new byte[4096];
           int bytesRead = -1;
            
           while ((bytesRead = inStream.read(buffer)) != -1) 
           {
               outStream.write(buffer, 0, bytesRead);
           }
            
           inStream.close();
           outStream.close();    
           
           if( ZipManager.Instance().Generated( resourcePath[1]) )
           {
               if(downloadFile.delete()) Logger.println(this, "Deleted Auto Generated ZipFile: " + downloadFile.getName());
           }
       }
       
       //--------------------------------------------------------------------------------
       // Get a corpus File from Scenario Storage. This version has the caller provide the full path
       // to the file.
       //------------------------------------------------------------------------
       if (resourcePath[0].equals("corpusfile"))
       {      
           String  fileName = CorpusServices.Instance().getBasePath();
           
           for( String uriEntry : resourcePath)
           {
               if (uriEntry.equals("corpusfile")) continue;
               
               fileName = fileName + File.separator + uriEntry;
           }
 
           File            downloadFile    = new File(fileName);
           FileInputStream inStream        = new FileInputStream(downloadFile);
            
           response.setContentType("application/octet-stream");
           response.setContentLength((int)downloadFile.length());
                         
           OutputStream outStream = response.getOutputStream();
            
           byte[] buffer = new byte[4096];
           int bytesRead = -1;
            
           while ((bytesRead = inStream.read(buffer)) != -1) 
           {
               outStream.write(buffer, 0, bytesRead);
           }
            
           inStream.close();
           outStream.close();     
       }

      
       
       //--------------------------------------------------------------------------------
       // RESTFul Path: /CDMS/corpus/store/<clusterId>/<scenarioId>/<vmfId>/<TestCaseSize>/<fileType>
       // FileType at the end of the URL will determine if this is a compressed set of test cases to
       // store. If it is omitted it will behave as a regular file storage.
        
       if( resourcePath[0].equals("store") )
       {  
           //Note: The tags are set in the header only if this is a single test case
           //If a zip file is sent instead, then the tags are parsed out of the filename (and this value will be null)
           String tags = request.getHeader("tags");
           
           int  numbytes = 0;
           
           TestCaseMsg testcaseMsg = new TestCaseMsg(Integer.parseInt(resourcePath[4]));
           testcaseMsg.setTags(tags);
           testcaseMsg.setClusterId(resourcePath[1]);
           testcaseMsg.setScenarioId(resourcePath[2]);
           testcaseMsg.setVmfId(resourcePath[3]);
           testcaseMsg.setFileType(UiUtil.notNull(resourcePath[5]));
           
           do
           {
               int bytesRead = request.getInputStream().read(testcaseMsg.getData(), numbytes, testcaseMsg.getSize() - numbytes);             
               numbytes     += bytesRead;
           } 
           while(numbytes < testcaseMsg.getSize() );
           
           if( numbytes != testcaseMsg.getSize() )
           {
               Logger.println(this, ">>>>STORED MSG["+numbytes+"] Does not Equal Message Size: " + testcaseMsg.getSize());     
           }
          
           if(testcaseMsg.getFileType().equalsIgnoreCase("ZIP"))
           {
               Logger.println(this, ">>Expanding Zip File of TestCases: " + testcaseMsg.getSize());     
                              
               String zipFile = CorpusServices.Instance().ExpandAndStoreTestCase(testcaseMsg);
               
               // Remove Zip File once Expanded 
               
               File myObj = new File(zipFile); 
               
               if(myObj.delete()) Logger.println(this, "Deleted testCase ZipFile: " + myObj.getName());
           }
           else
           {           
               // Store the testCase as part of the Scenarios Corpus.
               CorpusServices.Instance().StoreTestCase(testcaseMsg);
           }
           
           // Tell the VMFs in the cluster that new data is available
           CorpusServices.Instance().notifyNewCorpus(Integer.parseInt(testcaseMsg.getClusterId()));
                     
           // Respond to the Get                
           response.setContentType("text/plain");
           response.setCharacterEncoding("UTF-8");
           PrintWriter out = response.getWriter();
           out.println( "OK" );
           out.close();               
       }
       
       //--------------------------------------------------------------------------------
       // /CDMS/corpus/seeds/<scenarioid>/<vmfid>
       // parameters: tags, getMinCorpus
       // getMinCorpus=1 indicates we should get the minimized corpus rather than the seeds (if there is a minimized corpus)
       //        
       if( resourcePath[0].equals("seeds") )
       {    
           Logger.println("Getting Seeds for Scenario:" +  resourcePath[1]);

           int          scenarioId   = Integer.parseInt(resourcePath[1]);
           int          vmfId        = Integer.parseInt(resourcePath[2]);
           String       tagString    = request.getParameter("tags");
           String       getMinCorpus = (request.getParameter("getMinCorpus"));
           Gson         myGson       = new Gson();
           CorpusMsg    corpusMsg    = new CorpusMsg( CorpusServices.Instance().SeedList(scenarioId, tagString, Boolean.parseBoolean(getMinCorpus)) );
           
           // Zip the file list up up and return the zip file to the client
           
           String[]     zipFiles     = ZipManager.Instance().zipFiles(corpusMsg.getFiles(), vmfId);
           
           corpusMsg.setFiles(zipFiles);
           
           String       myJSON       = myGson.toJson(corpusMsg);
           
           response.setContentType("application/json");
           response.setCharacterEncoding("UTF-8");
           PrintWriter out = response.getWriter();
           out.println(myJSON);
           out.close();                  
       }
       //--------------------------------------------------------------------------------
       //RESTFul Path: /CDMS/corpus/whole/<clusterid>
       //
       //This is similar to "retrieve" only it grabs the whole corpus for a cluster, regardless
       //of whether any VMF ids are assigned to it
       
       if( resourcePath[0].equals("whole") )
       {   
           Logger.println("Retrieving Whole Corpus for Cluster:" +  resourcePath[1]);
           Gson           myGson    = new Gson();                    
           BufferedReader reader    = request.getReader();           
           String         clusterId = resourcePath[1];
                      

           // Set List of Files and new timestamp back to caller
           CorpusMsg corpusMsg = new CorpusMsg(CorpusServices.Instance().RetrieveUnfilteredCorpus(clusterId));
           
           corpusMsg.setTimestamp(String.valueOf(System.currentTimeMillis()));
           
           // Zip the file list up up and return the zip file to the client
           // VMF ID = 0 in the call to ZipManager
           String[] zipFiles = ZipManager.Instance().zipFiles(corpusMsg.getFiles(), 0);
           
           corpusMsg.setFiles(zipFiles);
            
           String   myJSON   = new Gson().toJson(corpusMsg);
           
           response.setContentType("application/json");
           response.setCharacterEncoding("UTF-8");
           PrintWriter out = response.getWriter();
           out.println(myJSON);
           out.close();                  
       }

       //--------------------------------------------------------------------------------
       //RESTFul Path: /CDMS/corpus/retrieve/<vmfId> 
       
       if( resourcePath[0].equals("retrieve") )
       {    
           Logger.println("Retrieving Corpus List for VMF:" +  resourcePath[1]);

           Gson           myGson    = new Gson();                    
           BufferedReader reader    = request.getReader();           
           char           buff[]    = new char[1024];            
           int            numbytes  = reader.read(buff);
           String         msg       = String.valueOf(buff).trim();  
           String         vmfId     = resourcePath[1];
                      
           CorpusMsg corpusMsg = myGson.fromJson(msg, CorpusMsg.class);
           
           // Set List of Files and new timestamp back to caller
           
           corpusMsg.setFiles(CorpusServices.Instance().RetrieveCorpus(corpusMsg, vmfId));
           
           corpusMsg.setTimestamp(String.valueOf(System.currentTimeMillis()));
           
           // Zip the file list up up and return the zip file to the client
           String[] fileList = corpusMsg.getFiles();
           String[] zipFiles = {};
           
           //Check to see if there was any data, if not, return an empty corpus message
           //(one that contains no zip file)
           if(fileList.length > 0)
           {
               zipFiles = ZipManager.Instance().zipFiles(fileList, Integer.parseInt(vmfId));
           }
           
           corpusMsg.setFiles(zipFiles);
           
            
           String   myJSON   = new Gson().toJson(corpusMsg);
           
           response.setContentType("application/json");
           response.setCharacterEncoding("UTF-8");
           PrintWriter out = response.getWriter();
           out.println(myJSON);
           out.close();                  
       }
       //--------------------------------------------------------------------------------
       //RESTFul Path: /CDMS/corpus/getCorpusView/<clusterfId> 
       
       if( resourcePath[0].equals("getCorpusView") )
       {    
           int             clusterId = Integer.parseInt(resourcePath[1]);
           String          tags      = UiUtil.notNull(request.getParameter("Tags"));                   
           
           Logger.println("Retrieving Entire Corpus List for Cluster:" +  clusterId +  " Tags: " + tags);
           
           ArrayList<TestCaseBean>  testcases = CorpusServices.Instance().RetrieveCorpusView(clusterId);
           ArrayList<TestCaseView>  tcList    = new ArrayList<TestCaseView>(testcases.size());
           ArrayList<ScenarioBean>  sbl       = (ArrayList<ScenarioBean>) DatabaseService.Instance().getScenarios(clusterId);      
           Hashtable<Integer, String> slookup = new  Hashtable<Integer, String>();
                   
           for( ScenarioBean sb : sbl )
           {
               slookup.put( sb.getId(), sb.getName() );
           }
           
           for( TestCaseBean testcase : testcases )
           {               
               if( (testcase.getTags().length() == 0) || (testcase.getTags().contains(tags)) )
               {
                   tcList.add( new TestCaseView( testcase, slookup.get(testcase.getScenarioId())) );    
               }
           }
           
           if( tcList.size() == 0 )
           {
               tcList.add(new TestCaseView(clusterId));
           }
           
           String  myJSON = new Gson().toJson(tcList);
           
           response.setContentType("application/json");
           response.setCharacterEncoding("UTF-8");
           PrintWriter out = response.getWriter();
           out.println(myJSON);
           out.close();                  
       }
       
        
       //--------------------------------------------------------------------------------
       //RESTFul Path: /CDMS/corpus/sync/<vmfId>/<clusterfId>/<scenarioId>/ {payload}
       
       if( resourcePath[0].equals("sync") )
       {    
           Gson           myGson     = new Gson();                    
           int            vmfId      = Integer.parseInt(resourcePath[1]);
           int            clusterId  = Integer.parseInt(resourcePath[2]);
           int            scenarioId = AppConfig.invalidId;
           BufferedReader reader     = request.getReader();           
           char           buff[]     = new char[1024];            
           String         msg        = new String();
           
            while(reader.read(buff) != -1 )
           {
               msg += String.valueOf(buff).trim(); 
               Arrays.fill(buff, '\0');
           }
            
           if( resourcePath.length > 3)
           {
               scenarioId       = Integer.parseInt(resourcePath[3]);      
               ScenarioBean sb  = DatabaseService.Instance().getScenario(scenarioId);
               clusterId        = sb.getClusterId();
           }

           CorpusMsg corpusMsg = myGson.fromJson(msg, CorpusMsg.class);            
           String[]  files     = corpusMsg.getFiles();
           Integer[] tcIds     = new Integer[files.length];
           int       tcIdIndex = 0;
           
           // Looking for _TCXXX_ which will contain the TestCase UID.
           for( String filename : files )
           {
               int index = filename.lastIndexOf("_TC");
               
               if( index > 0)
               {
                   index      += 3; // Skipping over _TC
                   int ucIndex = filename.indexOf("_", index);
                   
                   // Looking for the numbers after _TC and before the next underscore(_)
                   if( ucIndex > 0 ) 
                   {
                       String id          = filename.substring(index, ucIndex);       
                       tcIds[tcIdIndex++] = Integer.valueOf(id);
                   }
               }               
           }
           
           Logger.println( this, "Storing new Corpus  for CID:" + clusterId+ " SID:" + scenarioId + " Size:" + tcIds.length);
           
           // Create a new Corpus for the cluster and/or scemario
           
           CorpusBean corp = new CorpusBean(clusterId, scenarioId, System.currentTimeMillis() );
           
           DatabaseService.Instance().addCorpus(corp);
           
           CorpusToTestCaseBean corpusToTestCase = new CorpusToTestCaseBean();
           
           for( Integer testcaseId : tcIds )
           {
               corpusToTestCase.setCorpusId(corp.getId());
               corpusToTestCase.setTestcaseId(testcaseId);
               DatabaseService.Instance().addCorpusToTestCase(corpusToTestCase);               
           }
           
           ArrayList<TestCaseBean> clusterTCs = (ArrayList<TestCaseBean>)DatabaseService.Instance().getClusterTestCases(clusterId);

           for( TestCaseBean tc : clusterTCs)
           {
              if( !Arrays.stream(tcIds).anyMatch(i -> i == tc.getId()))
              {
                  // Delete the Test Case 
                  
                  DatabaseService.Instance().deleteTestCase( tc.getId());
                  
                  String FileBasePath        = CorpusServices.Instance().getScenarioPath( tc.getClusterId(), tc.getScenarioId() );                
                  File   CorpusTestCaseFile  = new File(FileBasePath + tc.getFilename() );

                  if( false == CorpusTestCaseFile.delete() )
                  {
                      Logger.println(this, "Count Not Delete FIle:" + CorpusTestCaseFile);
                  }
              }
                       
           }
      
           C2Msg  c2Msg  = new C2Msg();                   
           c2Msg.setClusterId( clusterId );
           c2Msg.setCommandId(C2CommandEnum.RESTART.Id()); 
           C2Services.Instance().BroadcastMessage(c2Msg);
           
           String  myJSON = new Gson().toJson(corp);          
           response.setContentType("application/json");
           response.setCharacterEncoding("UTF-8");
           PrintWriter out = response.getWriter();
           out.println(myJSON);
           out.close();                  
       }
   }  	
}
