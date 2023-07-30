<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE sqlMap PUBLIC "-//ibatis.apache.org//DTD SQL Map 2.0//EN" "http://ibatis.apache.org/dtd/sql-map-2.dtd">

<sqlMap>

    <!--                                                                --> 
    <!-- Insert a VMF                                           	  -->
    <!--                                                              --> 

    <insert id="addVMF" parameterClass="VMFBean">
      
      INSERT INTO VMF (Pid,ClusterId,ScenarioId,Name,Host,Kpi,Status,Reason) VALUES (#pid#,#clusterId#,#scenarioId#,#name#,#host#,#kpi#,#status#,#reason#)    
         
      <selectKey resultClass="Integer" keyProperty="uid">
            SELECT LAST_INSERT_ROWID() AS value
      </selectKey>  
          
   </insert>
   
   <!--                                                               --> 
   <!-- Update a VMF                                            	 -->
   <!--                                                               --> 
   <update id="updateVMF" parameterClass="VMFBean">
      
     UPDATE VMF
     SET  
            Kpi        = #kpi#,
            Status     = #status#,
            Reason     = #reason#,
            ClusterId  = #clusterId#,
            ScenarioId = #scenarioId#
            
     WHERE
            VMF.Uid    = #uid#
                   
   </update>
   
   
   <!--																--> 
   <!-- Get a List of VMFs											-->
   <!--																--> 
	
   <select id="getVMFs" parameterClass="Integer" resultClass="VMFBean">
 	
      SELECT *
      FROM    VMF
      WHERE   VMF.ScenarioId = #value#  
      
   </select>
   
   <!--																--> 
   <!-- Get a single VMF											-->
   <!--																--> 
	
   <select id="getVMF" parameterClass="Integer" resultClass="VMFBean">
   	
      SELECT *
      FROM   VMF 
      WHERE  VMF.Uid = #value#
      
    </select>
      
   <!--                                                             --> 
   <!-- Get VMF Count                                               -->
   <!--                                                             --> 
    
   <select id="getVMFCount" parameterClass="map" resultClass="Integer">
    
      SELECT COUNT(Uid) as count 
      FROM VMF 
      WHERE VMF.ScenarioId = #scenarioId#
      AND   VMF.Status    != #status#
       
   </select>

   
</sqlMap>