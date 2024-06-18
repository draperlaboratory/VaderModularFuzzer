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

import java.io.IOException;
import java.io.PrintWriter;
import java.net.HttpURLConnection;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.draper.utilities.Logger;

public abstract class ControllerServlet extends HttpServlet
{
	private static final long 			  serialVersionUID 	= 1L;

   public void init(ServletConfig config) throws ServletException
   {
      super.init(config);
   }

   protected void doGet(HttpServletRequest request, HttpServletResponse response)throws ServletException, IOException
   {
       try
       {
           processRequest(request, response);
       }
       catch(Exception e)
       {
           Logger.println( this, e );    
           response.setContentType("text/plain");
           response.setCharacterEncoding("UTF-8");
           response.setStatus(HttpURLConnection.HTTP_INTERNAL_ERROR);
           PrintWriter out = response.getWriter();
           out.println("Internal Error" );
           out.close();
       }  
   }

   protected void doPost(HttpServletRequest request, HttpServletResponse response)throws ServletException, IOException
   {
       try
       {
           processRequest(request, response);
       }
       catch(Exception e)
       {
           Logger.println( this, e );     
           response.setContentType("text/plain");
           response.setCharacterEncoding("UTF-8");
           response.setStatus(HttpURLConnection.HTTP_INTERNAL_ERROR);
           PrintWriter out = response.getWriter();
           out.println("Internal Error" );
           out.close();
       }
   }

   protected abstract void processRequest(HttpServletRequest request, HttpServletResponse response) throws Exception;
}
