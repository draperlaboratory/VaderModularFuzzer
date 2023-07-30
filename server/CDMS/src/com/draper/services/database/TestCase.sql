<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE sqlMap PUBLIC "-//ibatis.apache.org//DTD SQL Map 2.0//EN" "http://ibatis.apache.org/dtd/sql-map-2.dtd">

<sqlMap>

  <!--                                                                --> 
    <!-- Insert a TestCase                                            -->
    <!--                                                              --> 

    <insert id="addTestCase" parameterClass="TestCaseBean">
      
      INSERT INTO TestCase (TimeStamp,Filename,Tags,VmfId,ClusterId,ScenarioId) VALUES (#timestamp#,#filename#,#tags#,#vmfId#,#clusterId#,#scenarioId#)    
         
      <selectKey resultClass="Integer" keyProperty="id">
            SELECT LAST_INSERT_ROWID() AS value
      </selectKey>  
          
   </insert>
   
   <!--                                                               --> 
   <!-- Update a TestCase                                             -->
   <!--                                                               --> 
   <update id="updateTestCase" parameterClass="TestCaseBean">
      
     UPDATE TestCase
     SET  
            TimeStamp       = #timestamp#,
            Tags            = #tags#,
            Filename        = #filename#
            
     WHERE
            TestCase.Id     = #id#
                   
   </update>
   
   
   <!--																--> 
   <!-- Get a List of TestCases									    -->
   <!--																-->    
   <select id="getTestCases" parameterClass="map" resultClass="TestCaseBean">
 	
      SELECT *
      FROM    TestCase
      WHERE   TestCase.TimeStamp <![CDATA[ >= ]]> #timestamp#
      AND     TestCase.ClusterId = #clusterId#
   </select>
   
   <!--                                                             --> 
   <!-- Get a List of TestCases for a Cluster                       -->
   <!--                                                             -->    
   <select id="getClusterTestCases" parameterClass="Integer" resultClass="TestCaseBean">
    
      SELECT *
      FROM    TestCase
      WHERE   TestCase.ClusterId = #value#
        
   </select>
   
   <!--																--> 
   <!-- Get a single TestCase										-->
   <!--																--> 
	
   <select id="getTestCase" parameterClass="Integer" resultClass="TestCaseBean">
   	
      SELECT *
      FROM   TestCase 
      WHERE  id = #value#
      
    </select>
    
   <!--                                                             --> 
   <!-- Get TestCase Count                                          -->
   <!--                                                             --> 
    
   <select id="getTestCaseCount" parameterClass="Integer" resultClass="Integer">
    
      SELECT COUNT(Id) as count FROM TestCase WHERE TestCase.ClusterId = #value#
       
   </select>
      
   <!--                                                              --> 
   <!-- Delete a TestCase                                            -->
   <!--                                                              --> 
    
   <delete id="deleteTestCase" parameterClass="Integer">
    
      DELETE
      FROM   TestCase 
      WHERE  id = #value#
      
    </delete>
    
   
   
</sqlMap>