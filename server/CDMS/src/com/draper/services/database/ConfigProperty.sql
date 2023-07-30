<?xml version="1.0" encoding="UTF-8" ?>

<!DOCTYPE sqlMap
 PUBLIC "-//ibatis.apache.org//DTD SQL Map 2.0//EN"
    "http://ibatis.apache.org/dtd/sql-map-2.dtd">

<sqlMap>

   	<select id="getProperty" resultClass="String" parameterClass="String">
   	
   	   SELECT
         value
      	FROM ConfigProperty
      	WHERE name = #name#
      	
   	</select>

 	<update id="setProperty" parameterClass="ConfigProperty">
   	
      UPDATE ConfigProperty
      SET 
        value  = #value#
      WHERE 
      	  name = #name#
   	   
   	</update>

</sqlMap>
