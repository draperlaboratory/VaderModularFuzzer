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
package com.draper.services.corpus;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import com.draper.application.AppConfig;
import com.draper.services.c2.C2CommandEnum;
import com.draper.services.c2.C2Msg;
import com.draper.services.c2.C2Services;
import com.draper.services.database.CorpusBean;
import com.draper.services.database.CorpusToTestCaseBean;
import com.draper.services.database.DatabaseService;
import com.draper.services.database.ScenarioBean;
import com.draper.services.database.TestCaseBean;
import com.draper.services.database.VMFBean;
import com.draper.utilities.Logger;
import com.draper.utilities.UiUtil;

//---------------------------------------------------------------------------------------------------------------
//
//
//---------------------------------------------------------------------------------------------------------------     
public final class CorpusServices
{
	private				 	String				mStoragePath = null;
    private static final    CorpusServices      instance     = new CorpusServices();

    
    /****************************************************************************************
     * Instance pattern for singleton
     *
     */
    static public CorpusServices Instance()
    {       
        return instance;
    }
    

    /****************************************************************************************
     *
     */ 
    public synchronized void Initialize(String storagePath) throws Exception
    {
        mStoragePath = storagePath;		
    }
    
    /****************************************************************************************
     * 
     */
    public void CreateClusterStorage(int clusterId, int cloneClusterId ) throws Exception
    {
        File clusterDir = new File(this.getClusterPath(clusterId));
         
        if (!clusterDir.exists())
        {
            clusterDir.mkdirs();
        }     
        
        // Clone the new Cluster from a prior cluster if indicated
        
        if( cloneClusterId != AppConfig.invalidId )
        {
            // Copy seeds from previous cluster
            File cloneDir            = new File(this.getClusterPath(cloneClusterId));                      
            Path sourcePath         = Paths.get(cloneDir.getCanonicalPath());
            Path destinationPath    = Paths.get(clusterDir.getCanonicalPath());     
            
            Files.walk(sourcePath).forEach(source -> UiUtil.CopyFiles(source, destinationPath.resolve(sourcePath.relativize(source)))); 
        }
    }
      
    /****************************************************************************************
     * 
     */
    public void CreateScenarioStorage(int clusterId, int scenarioId) throws Exception
    {
        File ScenarioDir        =  new File(this.getScenarioPath(clusterId, scenarioId));
        File ScenarioSeedDir    =  new File(this.getScenarioSeedPath(clusterId, scenarioId));
        File ScenarioConfigDir  =  new File(this.getScenarioConfigPath(clusterId, scenarioId));

        if (!ScenarioDir.exists())
        {
            ScenarioDir.mkdirs();
        } 
        
        if (!ScenarioSeedDir.exists())
        {
            ScenarioSeedDir.mkdirs();
        } 
        
        if (!ScenarioConfigDir.exists())
        {
            ScenarioConfigDir.mkdirs();
        } 
    }
    
    /****************************************************************************************
     *  RetrieveUnfilteredCorpus 
     *  TODO(VADER-819): Make this more efficient using Database SQL
     *  This method will get all of the test cases in a cluster (with no filtering at all)
     */
    public synchronized String[] RetrieveUnfilteredCorpus(String clusterId) throws Exception
    {  
        
        // Lookup the corpus for this Cluster
        long timestamp = 0; //we don't filter by time in this call
        ArrayList<TestCaseBean> testCases   = (ArrayList<TestCaseBean>)DatabaseService.Instance().getTestCases(Integer.parseInt(clusterId),timestamp);
        ArrayList<String>       fileList    = new  ArrayList<String>();
       
        for( TestCaseBean testCase : testCases )
        {                    
            if( !testCase.getFilename().trim().isEmpty() )
            {
                fileList.add("cluster" + testCase.getClusterId() + "/scenario"  + testCase.getScenarioId() + "/" + testCase.getFilename() );
            }
            else
            {
                Logger.println(this, "EMPTY FileName In DB(" + testCase.getClusterId() + "," + testCase.getScenarioId() + "," + testCase.getId()+ ")" );
            }
        }
        
        String[] retArray = new String[fileList.size()];
        int      index    = 0;
        
        for( String file : fileList )
        {
            retArray[index++] = file;
        }
        
        return retArray;
    }
      
    /****************************************************************************************
     *  RetrieveCorpus
     *  TODO(VADER-819): Make this more efficient using Database SQL
     *  This method will get the testcases produced in the cluster based on a tiemstamp
     */
    public synchronized String[] RetrieveCorpus( CorpusMsg corpusMsg, String vmfId) throws Exception
    {  
        
        // Lookup the VMF
        
        long                    timestamp   = Long.parseLong(corpusMsg.getTimestamp());
        VMFBean                 vmf         = DatabaseService.Instance().getVMF(Integer.parseInt(vmfId));
        ArrayList<TestCaseBean> testCases   = (ArrayList<TestCaseBean>)DatabaseService.Instance().getTestCases(vmf.getClusterId(),timestamp);
        ArrayList<String>       fileList    = new  ArrayList<String>();
        String                  tags        = corpusMsg.getTags();
        boolean                 ignoreId    = (corpusMsg.getIgnoreVmfId() == 1);
        
        for( TestCaseBean testCase : testCases )
        {                    
            if( ( testCase.getVmfId() != vmf.getUid() ) || ignoreId )
            {
                if( !tags.isEmpty() ) // filter on tags supplied for testcases
                {
                    String[] tokens = tags.split(",");  
                    
                    for( String token : tokens )
                    {
                        if( testCase.getTags() != null )
                        {
                            if( testCase.getTags().contains(token) )                        
                            {
                                if( !testCase.getFilename().trim().isEmpty() )
                                {
                                    fileList.add("cluster" + testCase.getClusterId() + "/scenario"  + testCase.getScenarioId() + "/" + testCase.getFilename() );     
                                }
                                else
                                {
                                    Logger.println(this, "EMPTY FileName In DB(" + testCase.getClusterId() + "," + testCase.getScenarioId() + "," + testCase.getId()+ ")" );
                                }
                            }
                        }
                    }
                }
                else
                {
                    if( !testCase.getFilename().trim().isEmpty() )
                    {
                        fileList.add("cluster" + testCase.getClusterId() + "/scenario"  + testCase.getScenarioId() + "/" + testCase.getFilename() );
                    }
                    else
                    {
                        Logger.println(this, "EMPTY FileName In DB(" + testCase.getClusterId() + "," + testCase.getScenarioId() + "," + testCase.getId()+ ")" );
                    }
                }
            }
        }
        
        String[] retArray = new String[fileList.size()];
        int      index    = 0;
        
        for( String file : fileList )
        {
            retArray[index++] = file;
        }
        
        return retArray;
    }
    /****************************************************************************************
     *  RetrieveMinimizedCorpus
     *  This will provide the latest minimized corpus and every cluster 
     *  and scenario under the cluster
     */
    public  ArrayList<TestCaseBean> RetrieveMinimizedCorpus( int clusterId, int scenarioId, String tags ) throws Exception
    {       
        CorpusBean              corp         = null;
        ArrayList<TestCaseBean> tcList      =  new  ArrayList<TestCaseBean>();            
        String[]                tagTokens   = {};
        
        if( !tags.isEmpty() ) // this will be used to filter on tags supplied for testcases
        {
            tagTokens = tags.split(","); 
        }
        
        if( scenarioId != AppConfig.invalidId )
        {
            corp = DatabaseService.Instance().getCorpusforScenario(scenarioId);
        }
        // If we cannot find a corpus for the scenario then use the one for the cluster
        
        else if(clusterId != AppConfig.invalidId )
        {
            corp = DatabaseService.Instance().getCorpusforCluster(clusterId);          
        }
        
        if( corp != null )
        {        
            ArrayList<CorpusToTestCaseBean> testCaseIdList = (ArrayList<CorpusToTestCaseBean>)DatabaseService.Instance().getCorpusToTestCase(corp.getId());             
            
            for( CorpusToTestCaseBean testCaseId : testCaseIdList )
            {
                TestCaseBean tcb          = DatabaseService.Instance().getTestCase(testCaseId.getTestcaseId());
                boolean      keepTestCase = true;
                
                if(tagTokens.length > 0)
                {
                    //If we have any tags to filter on, use those to determine whether to keep the test case
                    keepTestCase = false;
                    
                    for( String tag : tagTokens )
                    {
                        if( tcb.getTags().contains(tag) )
                        {
                            keepTestCase = true;
                            break; //stop searching, at least one tage matched
                        }
                    }
                }

                if(true == keepTestCase)
                {
                    tcb.setTimestamp(corp.getTimestamp());
                    tcList.add(tcb);     
                }
            }
        }    
        
        return tcList;
    }
    
   /****************************************************************************************
     *  RetrieveWholeCorpus
     *  This will provide the minimized corpus and every cluster test case produced after the 
     *  minimized corpus was created
     */
    public  ArrayList<TestCaseBean> RetrieveCorpusView( int clusterId ) throws Exception
    {                            
        ArrayList<TestCaseBean> clustertestCases = (ArrayList<TestCaseBean>)DatabaseService.Instance().getClusterTestCases(clusterId);
   
        return clustertestCases;
    }

    /****************************************************************************************
     *  Get the configured seedlist or get the minimized Corpus Files if it exists
     */
    public String[] SeedList(int scenarioId, String tags, boolean getMinCorpus) throws Exception
    {  
        ScenarioBean             sb                = DatabaseService.Instance().getScenario(scenarioId);
        String[]                 scenarioSeeds     = new File(this.getScenarioSeedPath(sb.getClusterId(), sb.getId())).list();                          
        String[]                 fileList          = null;
        ArrayList<TestCaseBean>  tcMinList         = new  ArrayList<TestCaseBean>();
        
        //Check to see if Scenario required the minimized list as a priority over the seeds
        if( true == getMinCorpus)
        {
            ArrayList<TestCaseBean> tcScenarioMinList = RetrieveMinimizedCorpus(AppConfig.invalidId,  sb.getId(), tags );
           
            if( !tcScenarioMinList.isEmpty() )
            {
                tcMinList.addAll(tcScenarioMinList);
            }
            else
            {
                ArrayList<TestCaseBean>  tcClusterMinList = RetrieveMinimizedCorpus( sb.getClusterId(), AppConfig.invalidId, tags );
    
                tcMinList.addAll(tcClusterMinList);
            }
            
            if(tcMinList.size() != 0)
            {
                fileList  = new String[tcMinList.size()];
                
                for( int i = 0; i < tcMinList.size(); i++ )
                {
                    TestCaseBean tcb = tcMinList.get(i);
                    fileList[i]      = "cluster" + sb.getClusterId() +  "/" + "scenario" + tcb.getScenarioId() + "/" + tcb.getFilename();
                }
            }
        }
        
        // No Corpus found or not required
        if(fileList == null)
        {
                      fileList  = new String[scenarioSeeds.length];
                int   index     = 0;

                // Provide a list of Seeds selected for this scenario. We make this into a URI 
                // that will get attached to the RESTful call to download a file
                
                for( String scenarioSeed : scenarioSeeds )
                {
                    fileList[index++] = "cluster" + sb.getClusterId() +  "/" + "scenario" + scenarioId + "/" + "seeds" + "/" + scenarioSeed;
                }
        }
       
        // The Seeds are stored under the scenarioID 
        return fileList;
    }
    
    /****************************************************************************************
     * Stores each of the test cases in the provided zip file.  Call notifyNewCorpus with the cluster id after this 
     * to tell the VMF instances that new data is available.
     */
    public String  ExpandAndStoreTestCase(TestCaseMsg testcaseMsg) throws Exception
    {
        File             BaseDir = new File(this.getScenarioPath( Integer.parseInt(testcaseMsg.getClusterId()), Integer.parseInt(testcaseMsg.getScenarioId())));
        String           zipFN   = BaseDir + File.separator + "V" + testcaseMsg.getVmfId()  + "_" +  System.currentTimeMillis() + ".zip";             
        FileOutputStream fosZip  = new FileOutputStream(zipFN);

        fosZip.write(testcaseMsg.getData());        
        fosZip.close();
  
        // Read Zip File and Save the Test Cases in it
        ZipFile zipFile = new ZipFile(zipFN);
           
        Enumeration<? extends ZipEntry> entries = zipFile.entries();
            
        while (entries.hasMoreElements())
        {
            ZipEntry entry = entries.nextElement();

            if (!entry.isDirectory()) 
            {
                InputStream inputStream = zipFile.getInputStream(entry); 
                {       
                    int zipEntrySize = (int) entry.getSize();
                    TestCaseMsg tcFileInZip = new TestCaseMsg(testcaseMsg, zipEntrySize );
                    
                    // Set the tags
                    String fullFilename = new File(entry.getName()).getName();
                    String tags = fullFilename.substring(fullFilename.indexOf("_TAGS_") + 6);
                    tcFileInZip.setTags(tags);
                    
                    // Read the Zip File into the buffer
                    
                    int len = inputStream.readNBytes(tcFileInZip.getData(),0,zipEntrySize);
                    
                    if( len != zipEntrySize)
                    {
                        Logger.println( this, "Read["+len+"] misMatch Entry["+ zipEntrySize +"]:" + entry.getName() + " From ZipFile:" + zipFile.getName());
                    }
                    
                    // This is Noisy in the log. Just for Debug
                    //Logger.println( this, "Stored["+len+"] :" + entry.getName() + " From ZipFile:" + zipFile.getName() + " TAGS=" + tags);
                                      
                    fosZip.close();
                       
                    StoreTestCase(tcFileInZip);
                 }
            }
        }
        
        zipFile.close();
        
        return zipFN;
    }
    
    /****************************************************************************************
     * Stores a test case to disk and to the database.  Call notifyNewCorpus with the cluster id after this 
     * to tell the VMF instances that new data is available (this notification is not within this method so that
     * a single call can be made for the zip file version of this method).
     */
    public synchronized void StoreTestCase(TestCaseMsg testcaseMsg ) throws Exception
    {
        long         currTime   = System.currentTimeMillis();
        TestCaseBean tc         = new TestCaseBean();
        
        tc.setClusterId(Integer.parseInt(testcaseMsg.getClusterId()));
        tc.setScenarioId(Integer.parseInt(testcaseMsg.getScenarioId()));
        tc.setVmfId(Integer.parseInt(testcaseMsg.getVmfId()));
        tc.setFilename("");
        tc.setTimestamp(currTime);
        tc.setTags(testcaseMsg.getTags());
                 
        DatabaseService.Instance().addTestCase(tc);

        String FileBase          = "V" + testcaseMsg.getVmfId() + "_TC" + tc.getId() + "_" + currTime + ".bin";
        File  CorpusTestCaseDir  = new File(this.getScenarioPath( Integer.parseInt( testcaseMsg.getClusterId()  ), 
                                                                  Integer.parseInt( testcaseMsg.getScenarioId() )
                                                                 ));

        String tcFileName        = CorpusTestCaseDir + File.separator + FileBase;               
        FileOutputStream fos     = new FileOutputStream(tcFileName);

        fos.write(testcaseMsg.getData());
        
        fos.close();
        
        // Update Test Case with name of file on Disk
        
        tc.setFilename(FileBase);                 
        DatabaseService.Instance().updateTestCase(tc);
    }
    
    /**
     * BroadCast C2 update to Cluster that there are new test Cases available
     */
    public void notifyNewCorpus(int clusterId)
    {
        C2Msg  c2Msg  = new C2Msg();       
        
        c2Msg.setClusterId( clusterId );
        c2Msg.setCommandId(C2CommandEnum.NEW_CORPUS.Id()); 

        C2Services.Instance().BroadcastMessage(c2Msg);
    }
    
    /****************************************************************************************
    * Get the BasePath to Cluster storage
    */ 
    public String getBasePath() 
    {
       return mStoragePath;     
    }
    
    /****************************************************************************************
    * Get the BasePath to Cluster storage
    */ 
    public String getClusterPath(int clusterId) 
    {
       return (mStoragePath + File.separator  + "cluster" + clusterId + File.separator + "storage"  + File.separator);     
    }
        
    /****************************************************************************************
    * Get the BasePath to Cluster storage
    */ 
    public String getScenarioPath(int clusterId, int scenarioId) 
    {
       return (mStoragePath + File.separator  + "cluster" + clusterId + File.separator + "scenario" + scenarioId + File.separator);     
    }
    
    /****************************************************************************************
    * Get the Seed path for a scenario
    */ 
    public String getScenarioSeedPath(int clusterId, int scenarioId) 
    {
        return (this.getScenarioPath(clusterId, scenarioId) +  "seeds"  + File.separator);     
    }
    
    /****************************************************************************************
    * Get Get the Copnfig path for a scenario
    */ 
    public String getScenarioConfigPath(int clusterId, int scenarioId) 
    {
        return (this.getScenarioPath(clusterId, scenarioId) + "config" + File.separator);     
    }
}
