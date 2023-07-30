<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE sqlMap PUBLIC "-//ibatis.apache.org//DTD SQL Map 2.0//EN" "http://ibatis.apache.org/dtd/sql-map-2.dtd">

<sqlMap>

    <!--                                                                --> 
    <!-- Insert a Corpus                                            -->
    <!--                                                              --> 

    <insert id="addCorpus" parameterClass="CorpusBean">
      
      INSERT INTO Corpus (ClusterId,ScenarioId,TimeStamp) VALUES (#clusterId#,#scenarioId#,#timestamp#)    
         
      <selectKey resultClass="Integer" keyProperty="id">
            SELECT LAST_INSERT_ROWID() AS value
      </selectKey>  
          
   </insert>
    <!--                                                              --> 
    <!-- Insert a CorpusToTestCase                                    -->
    <!--                                                              --> 

    <insert id="addCorpusToTestCase" parameterClass="CorpusToTestCaseBean">
      
      INSERT INTO CorpusToTestCase (CorpusId,TestCaseId) VALUES (#corpusId#,#testcaseId#)    
         
      <selectKey resultClass="Integer" keyProperty="id">
            SELECT LAST_INSERT_ROWID() AS value
      </selectKey>  
          
   </insert>
   
   <!--                                                               --> 
   <!-- Update a Corpus                                               -->
   <!--                                                               --> 
   <update id="updateCorpus" parameterClass="CorpusBean">
      
     UPDATE Corpus
     SET  
            TimeStamp   = #timestamp#,
            ClusterId   = #clusterId#,     
            ScenarioId  = #scenarioId#     
     WHERE
            Corpus.Id   = #id#
                   
   </update>
   
   
   <!--                                                             --> 
   <!-- Get the latest Corpus for Cluster                           -->
   <!--                                                             --> 
    
   <select id="getCorpusforCluster" parameterClass="Integer" resultClass="CorpusBean">
    
      SELECT *
      FROM    Corpus
      WHERE   TimeStamp = (SELECT MAX(TimeStamp) FROM Corpus WHERE Corpus.ClusterId = #value#);
      
   </select>
   
   <!--                                                             --> 
   <!-- Get the latest Corpus for a Scenario                        -->
   <!--                                                             --> 
    
   <select id="getCorpusforScenario" parameterClass="Integer" resultClass="CorpusBean">
    
      SELECT *
      FROM    Corpus
      WHERE   Corpus.ScenarioId = #value#
      AND     TimeStamp = (SELECT MAX(TimeStamp) FROM Corpus);
      
   </select>
   
   <!--                                                             --> 
   <!-- Get a single Corpus                                       -->
   <!--                                                             --> 
    
   <select id="getCorpus" parameterClass="Integer" resultClass="CorpusBean">
    
      SELECT *
      FROM   Corpus 
      WHERE  Corpus.Id = #value#
      
   </select>

   <!--                                                             --> 
   <!-- Get a single Corpus                                       -->
   <!--                                                             --> 
    
   <select id="getCorpusToTestCase" parameterClass="Integer" resultClass="CorpusToTestCaseBean">
    
      SELECT *
      FROM   CorpusToTestCase
      WHERE  CorpusToTestCase.corpusId = #value#
      
   </select>

   
</sqlMap>