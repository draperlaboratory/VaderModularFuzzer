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
package com.draper.servlets;

import java.io.BufferedReader;
import java.io.PrintWriter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.draper.services.performance.PerformanceServices;
import com.draper.utilities.Logger;
import com.draper.utilities.UrlUtil;

public class KPIServlet extends ControllerServlet
{
    private static final long serialVersionUID = 2L;
    private static       long execCounter      = 0L;
    
    /*************************************************************************************************
    * 
    */
    protected void processRequest(HttpServletRequest request, HttpServletResponse response) throws Exception
    {        
        String[]    resourcePath = UrlUtil.getRestPath(request);
        
        if( resourcePath[0].equals("update") )
        {   
            BufferedReader reader = request.getReader();
            
            char buff[] = new char[1024];
             
            int numbytes =  reader.read(buff);
                      
            String msg = String.valueOf(buff).trim();
            
            if( (execCounter % 50) == 0 )
            {
                Logger.println(this, "KPI MSG : [" + numbytes+ "] "  + msg);     
            }
            
            execCounter++;
            
            PerformanceServices.Instance().HandleKPI(msg);
            
            response.setContentType("application/json");
            response.setCharacterEncoding("UTF-8");
            PrintWriter out = response.getWriter();
            out.println("{status:true}");
            out.close();                  
   
        }  
    }
}