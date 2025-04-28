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
package com.draper.services.database;

import java.sql.SQLException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.ibatis.sqlmap.client.SqlMapClient;

/******************************************************************* 
 * Provides services for managing persistent study
 * data. */
public class DatabaseService
{
    private static final DatabaseService instance = new DatabaseService();
    private SqlMapClient                 dbMap    = null;

    /****************************************************************** 
     * Instance Pattern
     * 
     * @return
     * @throws SQLException 
     */
    static public DatabaseService Instance()
    {
        return instance;
    }

    /****************************************************************** 
     * Initialize Class Data
     * 
     * @return
     * @throws SQLException 
     */
    public void Init(SqlMapClient sqlMap)
    {
        this.dbMap = sqlMap;
    }

    /****************************************************************** 
     * Get property
     * 
     * @return
     * @throws SQLException 
     */
    public String getProperty(String key) throws SQLException
    {
        return (String) this.dbMap.queryForObject("getProperty", key);
    }

    /****************************************************************** 
     * Set property
     * 
     * @return
     * @throws SQLException 
     */
    public void setProperty(String key, String value) throws SQLException
    {
        this.dbMap.update("setProperty", new ConfigProperty(key, value));
        return;
    }
    /****************************************************************** 
    * TABLE SIZE SECTION
    /******************************************************************/
    public int getTestCount(int clusterId) throws SQLException
    {
        int autoElement = (int) this.dbMap.queryForObject("getTestCaseCount", clusterId);
        return autoElement;
    }
    
    public int getVMFCount(int scenarioId, int status) throws SQLException
    {
        Map<String, Object> parms = new HashMap<String, Object>();
        parms.put("scenarioId", scenarioId);
        parms.put("status", status);
        
        int autoElement = (int) this.dbMap.queryForObject("getVMFCount", parms);
        return autoElement;
    }

    public int getScenarioCount(int clusterId) throws SQLException
    {
        int autoElement = (int) this.dbMap.queryForObject("getScenarioCount", clusterId);
        return autoElement;
    }
 
    public int getClusterCount() throws SQLException
    {
        int autoElement = (int) this.dbMap.queryForObject("getClusterCount");
        return autoElement;
    }
    /****************************************************************** 
    * DATABASE INSERT SECTION
    /******************************************************************/
  
    /****************************************************************** 
     * @return
     * @throws SQLException 
     */
    public boolean addCorpus(CorpusBean corp) throws SQLException
    {
        Integer newId = (Integer) this.dbMap.insert("addCorpus", corp);
        return (newId != -1);       
    }

    /****************************************************************** 
     * @return
     * @throws SQLException 
     */
    public boolean addCorpusToTestCase(CorpusToTestCaseBean corpusToTestCase) throws SQLException
    {
        Integer newId = (Integer) this.dbMap.insert("addCorpusToTestCase", corpusToTestCase);
        return (newId != -1);
    }

    /****************************************************************** 
     * @return
     * @throws SQLException 
     */
    public boolean addTestCase(TestCaseBean results) throws SQLException
    {
        Integer newId = (Integer) this.dbMap.insert("addTestCase", results);
        return (newId != -1);
    }

    /****************************************************************** 
     * @return
     * @throws SQLException 
     */
    public boolean addCluster(ClusterBean culster) throws SQLException
    {
        Integer newId = (Integer) this.dbMap.insert("addCluster", culster);
        return (newId != -1);
    }

    /****************************************************************** 
     * @return
     * @throws SQLException 
     */

    public synchronized boolean addVMF(VMFBean msg) throws SQLException
    {
        Integer newId = (Integer) this.dbMap.insert("addVMF", msg);

        return (newId != -1);
    }

    /****************************************************************** 
     * @return
     * @throws SQLException 
     */

    public synchronized boolean addScenario(ScenarioBean msg) throws SQLException
    {
        Integer newId = (Integer) this.dbMap.insert("addScenario", msg);

        return (newId != -1);
    }

    /****************************************************************** 
     * DATABASE QUERY SECTION
     /******************************************************************/
    
    /****************************************************************** 
     * @return
     * @throws SQLException 
     */
    public synchronized List<TestCaseBean> getTestCases(int clusterid, long timestamp) throws SQLException
    {  
        Map<String, Object> parms = new HashMap<String, Object>();
        parms.put("clusterId", clusterid);
        parms.put("timestamp", timestamp);
          
        return this.dbMap.queryForList("getTestCases", parms);
    }

    /****************************************************************** 
     * @return
     * @throws SQLException 
     */
    public TestCaseBean getTestCase(int id) throws SQLException
    {
        TestCaseBean autoElement = (TestCaseBean)this.dbMap.queryForObject("getTestCase", id);
        return autoElement;
    }
 
    /****************************************************************** 
     * @return
     * @throws SQLException 
     */
    public CorpusBean getCorpusforCluster(int id) throws SQLException
    {
        CorpusBean autoElement = (CorpusBean)this.dbMap.queryForObject("getCorpusforCluster", id);
        return autoElement;
    }
    /****************************************************************** 
     * @return
     * @throws SQLException 
     */
    public CorpusBean getCorpusforScenario(int id) throws SQLException
    {
        CorpusBean autoElement = (CorpusBean)this.dbMap.queryForObject("getCorpusforScenario", id);
        return autoElement;
    }
    
    /****************************************************************** 
     * @return
     * @throws SQLException 
     */
    public List<CorpusToTestCaseBean> getCorpusToTestCase(int id) throws SQLException
    {
        return this.dbMap.queryForList("getCorpusToTestCase", id);
    }
    
    
    /****************************************************************** 
     * @return
     * @throws SQLException 
     */
    public List<TestCaseBean> getClusterTestCases(int clusterId)  throws SQLException
    {
        return this.dbMap.queryForList("getClusterTestCases", clusterId);
    }

    /****************************************************************** 
     * @return
     * @throws SQLException 
     */
    public synchronized List<ClusterBean> getClusters() throws SQLException
    {
        return this.dbMap.queryForList("getClusters");
    }
    /****************************************************************** 
     * @return
     * @throws SQLException 
     */
    public synchronized ClusterBean getCluster(int id) throws SQLException
    {
        ClusterBean autoElement = (ClusterBean)this.dbMap.queryForObject("getCluster", id);

        return autoElement;
     }

    /****************************************************************** 
     * @return
     * @throws SQLException 
     */
    public synchronized List<ScenarioBean> getScenarios(int clusterId) throws SQLException
    {
        return this.dbMap.queryForList("getScenarios", clusterId );
    }

    /****************************************************************** 
     * @return
     * @throws SQLException 
     */
    public synchronized ScenarioBean getScenario(int id) throws SQLException
    {
        ScenarioBean autoElement = (ScenarioBean)this.dbMap.queryForObject("getScenario", id);

        return autoElement;
     }
    
    /****************************************************************** 
     * @return
     * @throws SQLException 
     */
    public synchronized List<VMFBean> getVMFs(int scenarioId) throws SQLException
    {
        return this.dbMap.queryForList("getVMFs", scenarioId);
    }

    /****************************************************************** 
     * @return
     * @throws SQLException 
     */
    public synchronized VMFBean getVMF(int uid) throws SQLException
    {
        VMFBean autoElement = (VMFBean) this.dbMap.queryForObject("getVMF", uid);

        return autoElement;
    }

    /****************************************************************** 
     * DATABASE UPDATE SECTION
     /******************************************************************/
    

   /****************************************************************** 
     * @return
     * @throws SQLException 
     */
    public synchronized void updateCluster(ClusterBean cb) throws SQLException
    {
        this.dbMap.update("updateCluster", cb);
        return;
    }

    /****************************************************************** 
     * @return
     * @throws SQLException
     */
    public synchronized void updateScenario(ScenarioBean sb) throws SQLException
    {
        this.dbMap.update("updateScenario", sb);
        return;
    }

    /****************************************************************** 
     * @return
     * @throws SQLException 
     */
    public synchronized void updateTestCase(TestCaseBean tb) throws SQLException
    {
        this.dbMap.update("updateTestCase", tb);
        return;
    }

    /****************************************************************** 
     * @return
     * @throws SQLException 
     */
    public synchronized void updateVMF(VMFBean vb) throws SQLException
    {
        this.dbMap.update("updateVMF", vb);
        return;
    }
    
    /****************************************************************** 
     * DATABASE DELETE SECTION
     /******************************************************************/
 
    /****************************************************************** 
     * @return
     * @throws SQLException 
     */
    public void deleteTestCase(int id) throws SQLException
    {
        this.dbMap.delete("deleteTestCase", id);
        return;     
    }
    
    /****************************************************************** 
     * @return
     * @throws SQLException 
     */
 
    public void deleteScenario(int id) throws SQLException
    {
        this.dbMap.delete("deleteScenario", id);
        return;     
   } 
}