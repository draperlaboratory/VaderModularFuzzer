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
package com.draper.utilities;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.Calendar;
import java.util.Date;

public class Logger
{
   private static final Calendar 	CALENDAR 				= Calendar.getInstance();
   private static 		boolean 	stdoutEcho 				= true; 
   private static 		Date 		lastLogEntryTime        = new Date();
   private static 		PrintWriter logWriter;
   private static 		String 		fileBase; 
   private static       String      logFileName;
      
   public static void initialize(String fileBase, Date logStartTime, boolean useStdOut ) 
   {
       File logFile = null;
       
       try
       {
          Logger.fileBase = fileBase;
          
          logFile = new File(fileBase + "_" + UiUtil.GPXDATE_FORMAT.format(logStartTime) + ".txt");
          
          if (!logFile.getParentFile().exists())
          {
              logFile.getParentFile().mkdirs();
          }
          if (!logFile.exists())
          {
              logFile.createNewFile();
          }
         
          logWriter        = new PrintWriter(new BufferedWriter(new FileWriter(logFile, true)));
          lastLogEntryTime = logStartTime;
       }
       catch( Exception e )
       {
           e.printStackTrace();
       }
       
       logFileName = logFile.getAbsolutePath();
       stdoutEcho  = useStdOut;
   }
   
   public static synchronized void println(Object source, String msg, Exception e)
   {
      // Check if it's time to roll the log file over to a new day.
      CALENDAR.setTime(lastLogEntryTime);
      int lastEntryDayOfYear = CALENDAR.get(Calendar.DAY_OF_YEAR);
      Date now = new Date();
      CALENDAR.setTime(now);
      
      if (lastEntryDayOfYear != CALENDAR.get(Calendar.DAY_OF_YEAR))
      {
         close();
         initialize(fileBase, now, stdoutEcho);
      }
      
      String timestamp = UiUtil.FULL_TIMESTAMP_FORMAT.format(now);
      String className = "";
      
      if (source != null)
      {
         String classFullName = source.getClass().getName();
         className = classFullName.substring(classFullName.lastIndexOf(".") + 1) + ": ";
      }
      
      if (msg != null)
      {
         if (logWriter != null)
         {
            logWriter.println(timestamp + "  " + className + msg);
         }
         if (stdoutEcho)
         {
            System.out.println(timestamp + "  " + className + msg);
         }
      }
      
      if (e != null)
      {
         if (logWriter != null)
         {
            logWriter.println(timestamp + "  " + className + e.toString());
         }
         if (stdoutEcho)
         {
            System.out.println(timestamp + "  " + className + e.toString());
         }
         
         for (StackTraceElement ste : e.getStackTrace())
         {
            if (logWriter != null)
            {
               logWriter.println("\t\t" + ste.toString());
            }
            if (stdoutEcho)
            {
               System.out.println("\t\t" + ste.toString());
            }
         }
      }
      
      if (logWriter != null)
      {
         logWriter.flush();
      }
   }
   
   public static void println(Object source, String msg)
   {
      println(source, msg, null);
   }
   
   public static void println(Object source, Exception e)
   {
      println(source, null, e);
   }
   
   public static void println(String msg)
   {
      println(null, msg, null);
   }
   
   public static void println(Exception e)
   {
      println(null, null, e);
   }
   
   public static synchronized void close()
   {
      if (logWriter != null)
      {
         logWriter.close();
      }
   }
   
   public static final String getLogFileName()
   {
       return logFileName;
   }

   public static boolean getStdoutEcho() 
   {
       return stdoutEcho;
   }
}
