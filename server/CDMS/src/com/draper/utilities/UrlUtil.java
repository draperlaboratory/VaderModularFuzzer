/* =============================================================================
 * Vader Modular Fuzzer (VMF)
 * Copyright (c) 2021-2023 The Charles Stark Draper Laboratory, Inc.
 * <vader@draper.com>
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
package com.draper.utilities;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.Map;
import java.util.Properties;
import java.util.StringTokenizer;

import javax.servlet.http.HttpServletRequest;

import org.json.JSONObject;

/***********************************************************************************
 * Class for common convenient URL utility functions.
 */
public class UrlUtil
{
   /***********************************************************************************
    * 
    */
   public static String appRoot(HttpServletRequest request)
   {
	  String appRoot = "/";
	   
      if (request.getRequestURI().startsWith(request.getContextPath()))
      {	 
    	  appRoot = request.getContextPath() + "/";
      }
            
      return appRoot;
   }
   
   /***********************************************************************************
    * Parse a Comma Separated List of Key/Value Pairs
    */
   public static Properties getProperties(String args)
   {      
       Properties props =  new java.util.Properties();
       String     line  = new String("");

       // Clear Properties and Open Configuration file
       
       props.clear();
       
       // Read lines until end of file is reached
       
       StringTokenizer st = new StringTokenizer(args, ",", false);
          
       while(st.hasMoreTokens())
       {
           line = st.nextToken();
       
           int keyindex = line.indexOf('=');
       
           if (keyindex == -1) continue;
       
           String key_str   = line.substring(0, keyindex).trim();
           String value_str = line.substring(keyindex + 1).trim();
       
           props.put(key_str, value_str);
       }
       
       return props;
   }
   
   /***********************************************************************************
	* Prepares a string array containing the path elements of the incoming request URL that
	* follow the application context and servlet mapping.
	*/
   public static String[] getRestPath(HttpServletRequest request)
   {
      String requestUri = request.getRequestURI();
      
      // Strip of the app context path and servlet path.
      requestUri = requestUri.substring(request.getContextPath().length() +
    		  					        request.getServletPath().length()  );
      
      // Strip of any leading or trailing slashes.
      if (requestUri.startsWith("/"))
      {
         requestUri = requestUri.substring(1);
      }
      if (requestUri.endsWith("/"))
      {
         requestUri = requestUri.substring(0, requestUri.length() - 1);
      }
      
      return requestUri.split("/");
   }
   
   /***********************************************************************************
    * Prepares a string containing a comma separated list of Parameters and Values
    * Will be returned as [P=V]
    */
   public static String getParameters(HttpServletRequest request)
   {
       Enumeration<String>  names     = request.getParameterNames();
       Iterator<String>     iterator  = names.asIterator();
       String               paramList = new String();
      
       if( iterator.hasNext() ) {  paramList += "("; }
       
       while( iterator.hasNext() )
       { 
           String parameter = iterator.next();
           
           paramList  += parameter + "=" + request.getParameter(parameter.toString());           
           paramList  += ( iterator.hasNext() ) ? "," : ")";
       }
       
       return paramList;
   }
       
   /***********************************************************************************
    * Checks for a null access and returns an empty string in its place for
    * JSON parsing
    */
   public static String getValue(JSONObject obj, String field)
   {
	   	String ret = null;
	   	
		if( false == obj.isNull(field) )
		{
			ret = obj.getString(field);
		}
		else
		{
			ret = new String("");
		}

		return ret;
   }
   
	/***********************************************************************************
	 * Read the response off of the connection
	 */
   	public static String doGet(URL url, Hashtable<String,String> requestProperties ) throws Exception
	{
		HttpURLConnection 	conn = (HttpURLConnection)url.openConnection();
		
		conn.setRequestMethod("GET");
		conn.setReadTimeout(180 * 1000);
		conn.setConnectTimeout(180 * 1000);
		conn.setUseCaches(false);

		for( Map.Entry<String,String> entry : requestProperties.entrySet() ) 
		{
		    String key   = entry.getKey();
		    String value = entry.getValue();	
		    
		    conn.setRequestProperty(key, value );
		}
		
       // Invoke the Call and get the response from the GET        
		String json = UrlUtil.readResponse( conn );	
		
		return json;
	}

    /***********************************************************************************
     * Read the response off of the connection
     */
    public static String doPut(URL url, Hashtable<String,String> requestProperties, String postData ) throws Exception
    {
        HttpURLConnection  conn = (HttpURLConnection)url.openConnection();
        
        conn.setRequestMethod("PUT");
        conn.setReadTimeout(180 * 1000);
        conn.setConnectTimeout(180 * 1000);
        conn.setUseCaches(false);
        conn.setDoOutput(true);

        for( Map.Entry<String,String> entry : requestProperties.entrySet() ) 
        {
            String key   = entry.getKey();
            String value = entry.getValue();    
            
            conn.setRequestProperty(key, value );
        }
                
        DataOutputStream wr = new DataOutputStream(conn.getOutputStream());
        wr.writeBytes(postData);
        wr.flush();
        wr.close();

        // Invoke the Call and get the response from the GET        
        String json = UrlUtil.readResponse( conn ); 
        
        return json;
    }
    
	/***********************************************************************************
	 * Read the response off of the connection
	 */
   	public static String doPost(URL url, Hashtable<String,String> requestProperties, String postData ) throws Exception
	{
		HttpURLConnection 	conn = (HttpURLConnection)url.openConnection();
		
		conn.setRequestMethod("POST");
		conn.setReadTimeout(180 * 1000);
		conn.setConnectTimeout(180 * 1000);
		conn.setUseCaches(false);
		conn.setDoOutput(true);

		for( Map.Entry<String,String> entry : requestProperties.entrySet() ) 
		{
		    String key   = entry.getKey();
		    String value = entry.getValue();	
		    
		    conn.setRequestProperty(key, value );
		}
				
		DataOutputStream wr = new DataOutputStream(conn.getOutputStream());
		wr.writeBytes(postData);
		wr.flush();
		wr.close();

		// Invoke the Call and get the response from the GET        
		String json = UrlUtil.readResponse( conn );	
		
		return json;
	}

	/***********************************************************************************
	 * Read the response off of the connection
	 */
   	public static String readResponse(HttpURLConnection conn) throws Exception
	{
		int 			responseCode 		= conn.getResponseCode();
		String 			result				= null;
		BufferedReader 	in 					= null;
		StringBuffer 	response 			= new StringBuffer();
		String 			inputLine			= null;
		boolean			error				= false;
		
		if ((responseCode == HttpURLConnection.HTTP_OK)      ||
		    (responseCode == HttpURLConnection.HTTP_CREATED) ||
		    (responseCode == HttpURLConnection.HTTP_ACCEPTED))
		{
			in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
		}
		else
		{
			error 	= true;
			in 		= new BufferedReader(new InputStreamReader(conn.getErrorStream()));			
		}
		
		while ((inputLine = in.readLine()) != null) 
		{
			response.append(inputLine);
		}
		
		in.close();

		//Get Result
		result = response.toString();

		if( true == error )
		{
			result = "{responseCode: " + responseCode + " " + result + "}";
			throw new Exception(result);
		}
		
		return result;
	}   
}
