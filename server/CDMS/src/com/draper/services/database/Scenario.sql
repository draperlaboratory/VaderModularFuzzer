<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE sqlMap PUBLIC "-//ibatis.apache.org//DTD SQL Map 2.0//EN" "http://ibatis.apache.org/dtd/sql-map-2.dtd">

<sqlMap>

  <!--                                                                --> 
    <!-- Insert a Scenario                                            -->
    <!--                                                              --> 

    <insert id="addScenario" parameterClass="ScenarioBean">
      
      INSERT INTO Scenario (ClusterId,Name,Type,Capacity,FuzzerCount,State) VALUES (#clusterId#,#name#,#type#,#capacity#,#fuzzerCount#,#state#)    
         
      <selectKey resultClass="Integer" keyProperty="id">
            SELECT LAST_INSERT_ROWID() AS value
      </selectKey>  
          
   </insert>
   
   <!--                                                               --> 
   <!-- Update a Scenario                                             -->
   <!--                                                               --> 
   <update id="updateScenario" parameterClass="ScenarioBean">
      
     UPDATE Scenario
     SET  
            Name         = #name#,
            Type         = #type#,
            Capacity     = #capacity#,
            FuzzerCount  = #fuzzerCount#,
            State        = #state#
            
     WHERE
            Scenario.Id   = #id#
                   
   </update>
   
   
   <!--                                                             --> 
   <!-- Get a List of Scenarios                                     -->
   <!--                                                             --> 
    
   <select id="getScenarios" parameterClass="Integer" resultClass="ScenarioBean">
    
      SELECT *
      FROM    Scenario
      WHERE   Scenario.ClusterId = #value#
      
   </select>
   
   <!--                                                             --> 
   <!-- Get a single Scenario                                       -->
   <!--                                                             --> 
    
   <select id="getScenario" parameterClass="Integer" resultClass="ScenarioBean">
    
      SELECT *
      FROM   Scenario 
      WHERE  Scenario.Id = #value#
      
    </select>
   
   <!--                                                             --> 
   <!-- Get Scenario Count                                          -->
   <!--                                                             --> 
    
   <select id="getScenarioCount" parameterClass="Integer" resultClass="Integer">
    
      SELECT COUNT(Id) as count FROM Scenario WHERE Scenario.ClusterId = #value#
       
   </select>
   
   
   <!--                                                              --> 
   <!-- Delete a Scenario                                            -->
   <!--                                                              --> 
    
   <delete id="deleteScenario" parameterClass="Integer">
    
      DELETE
      FROM   Scenario 
      WHERE  id = #value#
      
    </delete>

</sqlMap>