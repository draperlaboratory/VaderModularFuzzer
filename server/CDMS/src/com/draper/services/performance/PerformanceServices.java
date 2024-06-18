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
package com.draper.services.performance;


import java.util.ArrayList;

import com.draper.services.database.ClusterBean;
import com.draper.services.database.DatabaseService;
import com.draper.services.database.ScenarioBean;
import com.draper.services.database.VMFBean;
import com.draper.utilities.KVPair;
import com.google.gson.Gson;

//---------------------------------------------------------------------------------------------------------------
//
//
//---------------------------------------------------------------------------------------------------------------     
public final class PerformanceServices
{
    private static final    PerformanceServices instance            = new PerformanceServices();    
    private int                                 registeredFuzzers   = 0;

    
    /****************************************************************************************
     * Instance pattern for singleton
     *
     */
    static public PerformanceServices Instance()
    {       
        return instance;
    }
    
    /****************************************************************************************
     * CTOR
     *
     */
    public PerformanceServices()
    {
        this.registeredFuzzers = 0;
    }
    
    /****************************************************************************************
     * Get the Registered Fuzzers for the System
     *
     */
    public int getRegisteredFuzzers()
    {
        return this.registeredFuzzers;
    }
    
    /****************************************************************************************
     * Set the Registered Fuzzer Count
     *
     */    
    public synchronized void setRegisteredFuzzers(int registeredFuzzers)
    {
        if( registeredFuzzers < 0 ) registeredFuzzers = 0;
        
        this.registeredFuzzers = registeredFuzzers;
    }
 
    /****************************************************************************************
     *  Thread body of the Service. All work gets done here
     */
    public synchronized boolean HandleKPI(String msg) throws Exception
    {  
        KPIMsg kpiMsg = new Gson().fromJson( msg, KPIMsg.class);               
                       
        // Find the VMF and update it Status
        
        VMFBean theVMF = DatabaseService.Instance().getVMF(kpiMsg.getUid());
        
        theVMF.setJson(msg);
         
        DatabaseService.Instance().updateVMF(theVMF);
        
        return true;

    }
    
    /****************************************************************************************
     *  Thread body of the Service. All work gets done here
     */
    public synchronized PerformanceView GetPerformace( int clusterId ) throws Exception
    {             
        ClusterBean                 cb              = DatabaseService.Instance().getCluster(clusterId);    
        ArrayList<ClusterBean>      cbl             = (ArrayList<ClusterBean>)DatabaseService.Instance().getClusters();;               
        ArrayList<ScenarioBean>     sbl             = (ArrayList<ScenarioBean>)DatabaseService.Instance().getScenarios(cb.getId());               
        ArrayList<PerformanceData>  sdataList       = new ArrayList<PerformanceData>();
        ArrayList<PerformanceData>  cdataList       = new ArrayList<PerformanceData>();
        int                         allocatedFuzzer = 0;
        
        // Go over Selected CLuster and update Scenario Data
        
        for( ScenarioBean sb : sbl )
        {      
            ArrayList<KVPair>  sKV    = new ArrayList<KVPair>();
            KVPair             sAF    = new KVPair("ACTIVE",String.valueOf(sb.getFuzzerCount()) );
            KVPair             sCAP   = new KVPair("CAP",   String.valueOf(sb.getCapacity()) );
            KVPair             sSTATE = new KVPair("STATE", sb.getState() );
            KVPair             sTYPE  = new KVPair("TYPE", sb.getType() );
    
            sKV.add(sAF);
            sKV.add(sCAP);
            sKV.add(sSTATE);
            sKV.add(sTYPE);
                           
            PerformanceData sdata = new PerformanceData(sb.getId(), sKV );
            
            sdataList.add(sdata);                  
        }
        
        
        // Go thru all Clusters to Update the state and the Test Case counts
        for( ClusterBean cluster : cbl )
        {      
            int                corpusSize = DatabaseService.Instance().getTestCount(cluster.getId());
            ArrayList<KVPair>  cKV        = new ArrayList<KVPair>();
            KVPair             cTCF       = new KVPair("TESTCASE", String.valueOf(corpusSize) );
            KVPair             cSTATE     = new KVPair("STATE",   cluster.getState() );
    
            cKV.add(cTCF);
            cKV.add(cSTATE);
            
            PerformanceData cdata = new PerformanceData(cluster.getId(), cKV );
            
            cdataList.add(cdata);          
            
            sbl  = (ArrayList<ScenarioBean>)DatabaseService.Instance().getScenarios(cluster.getId());               

            for( ScenarioBean sb : sbl )
            {      
                allocatedFuzzer += sb.getFuzzerCount();
            }
    
        }               
                   
        PerformanceView pv = new PerformanceView();
        pv.setScenarios(sdataList);
        pv.setClusters(cdataList);
        
        pv.setUnallocFuzzerSize(pv.getRegFuzzerSize() - allocatedFuzzer);
        
        
        return pv;  
    }
    
    /****************************************************************************************
     *  Push KPIs to connected  source 
     */
    public void PublishKPI(String msg) throws Exception
    {  
    }

    /****************************************************************************************
     *  Push KPIs to connected  source 
     */
    public void CalculaeKPI(String msg) throws Exception
    {  
    }    
}
