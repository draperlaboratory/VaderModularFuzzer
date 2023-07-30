<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE sqlMap PUBLIC "-//ibatis.apache.org//DTD SQL Map 2.0//EN" "http://ibatis.apache.org/dtd/sql-map-2.dtd">

<sqlMap>

  <!--                                                                --> 
    <!-- Insert a Cluster                                           	  -->
    <!--                                                              --> 

    <insert id="addCluster" parameterClass="ClusterBean">
      
      INSERT INTO Cluster (Name,Description,State,Edit) VALUES (#name#,#description#,#state#,#edit#)    
         
      <selectKey resultClass="Integer" keyProperty="id">
            SELECT LAST_INSERT_ROWID() AS value
      </selectKey>  
          
   </insert>
   
   <!--                                                               --> 
   <!-- Update a Cluster                                              -->
   <!--                                                               --> 
   <update id="updateCluster" parameterClass="ClusterBean">
      
     UPDATE Cluster
     SET  
            Name         = #name#,
            Description  = #description#,
            Edit         = #edit#,
            State        = #state#
            
     WHERE
            Cluster.Id   = #id#
                   
   </update>
   
   
   <!--																--> 
   <!-- Get a List of Clusters											-->
   <!--																--> 
	
   <select id="getClusters" resultClass="ClusterBean">
 	
      SELECT *
      FROM    Cluster
        
   </select>
   
   <!--																--> 
   <!-- Get a single Cluster											-->
   <!--																--> 
	
   <select id="getCluster" parameterClass="Integer" resultClass="ClusterBean">
   	
      SELECT *
      FROM   Cluster 
      WHERE  Id = #value#
      
    </select>
    
   <!--                                                             --> 
   <!-- Get Scenario Count                                          -->
   <!--                                                             --> 
    
   <select id="getClusterCount">
    
      SELECT COUNT(Id) as count FROM Cluster
       
   </select>
   
   
</sqlMap>