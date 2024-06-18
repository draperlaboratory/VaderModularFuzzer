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
package com.draper.servlets;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.HttpURLConnection;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.draper.services.corpus.CorpusServices;
import com.draper.services.database.DatabaseService;
import com.draper.services.database.VMFBean;
import com.draper.services.registration.RegistrationServices;
import com.draper.utilities.Logger;
import com.draper.utilities.UrlUtil;

public class RegistrationServlet extends ControllerServlet
{ 
    private static final long serialVersionUID = 2L;
    
    /*************************************************************************************************
    * 
    */
    protected void processRequest(HttpServletRequest request, HttpServletResponse response) throws Exception
    {
        String[] resourcePath = UrlUtil.getRestPath(request);
 
        //---------------------------------------------------------------------------------------------
                
        if( resourcePath[0].equals("register") )
        {          
           BufferedReader reader = request.getReader();
            
           char buff[] = new char[1024];
            
           int numbytes =  reader.read(buff);

           String msg = String.valueOf(buff).trim();
                          
           Logger.println(this, "REG MSG : [" + numbytes+ "] "  + msg);     
           
           String myJSON = RegistrationServices.Instance().HandleRegistration(msg);
           
           Logger.println(this, "REG RESP MSG: " + myJSON );
           
           response.setContentType("application/json");
           response.setCharacterEncoding("UTF-8");
           PrintWriter out = response.getWriter();
           out.println(myJSON);
           out.close();          
        } 
        
        //---------------------------------------------------------------------------------------------
      
        if( resourcePath[0].equals("status") )
        {   
            BufferedReader reader = request.getReader();
            
            char buff[] = new char[1024];
             
            int numbytes =  reader.read(buff);

            String msg = String.valueOf(buff).trim();

            Logger.println(this, "REG STATUS MSG : [" + numbytes+ "] "  + msg);     

            String myJSON = RegistrationServices.Instance().HandleRegistrationStatus(msg);
           
            response.setContentType("application/json");
            response.setCharacterEncoding("UTF-8");
            PrintWriter out = response.getWriter();
            out.println(myJSON);
            out.close();          
        } 
        
        //---------------------------------------------------------------------------------------------
               
        if( resourcePath[0].equals("tasking") )
        {   
            Logger.println("Getting Tasking for VMF.UID:" +  resourcePath[1]);
 
            try
            {
                String myJSON = RegistrationServices.Instance().HandleTasking(resourcePath[1]);
                
                Logger.println(this, "TASKING RESP MSG: " + myJSON );
                           
                response.setContentType("application/json");
                response.setCharacterEncoding("UTF-8");
                PrintWriter out = response.getWriter();
                out.println(myJSON);
                out.close();     
            }
            catch(Exception e )
            {
                Logger.println( this, e );     
                response.setContentType("application/json");
                response.setCharacterEncoding("UTF-8");
                response.setStatus(HttpURLConnection.HTTP_UNAVAILABLE);
                PrintWriter out = response.getWriter();
                out.println( e.getMessage() );
                out.close();
            }
        }
        
        //--------------------------------------------------------------------------------
        // Retrieve a configuration file for the VMF
        //--------------------------------------------------------------------------------
        if (resourcePath[0].equals("file")) 
        {               
            String          uid             = (String)resourcePath[1];  
            String          file            = (String)resourcePath[2];  
            VMFBean         vmf             = DatabaseService.Instance().getVMF(Integer.parseInt(uid));
            String          fileName        = CorpusServices.Instance().getScenarioConfigPath(vmf.getClusterId(),vmf.getScenarioId()) +  file;
            File            downloadFile    = new File(fileName);
            FileInputStream inStream        = new FileInputStream(downloadFile);
             
            response.setContentType("application/octet-stream");
            response.setContentLength((int)downloadFile.length());
                          
             OutputStream outStream = response.getOutputStream();
             
            Logger.println( this, "Sending Config File: " + fileName);    
             
            byte[] buffer = new byte[4096];
            int bytesRead = -1;
             
            while ((bytesRead = inStream.read(buffer)) != -1) 
            {
                outStream.write(buffer, 0, bytesRead);
            }
             
            inStream.close();
            outStream.close();     
        }
    }
}