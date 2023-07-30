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

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.time.Duration;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

/**
 * Class for common convenient user interface utility functions.
 */
public class UiUtil
{
   public static final DateFormat FULL_MONTH_ONLY 	        = new SimpleDateFormat("MMMM");
   public static final DateFormat DAY_NUM_ONLY 		        = new SimpleDateFormat("dd");
   public static final DateFormat YEAR_ONLY 		        = new SimpleDateFormat("yyyy");
   public static final DateFormat TIME_FORMAT 		        = new SimpleDateFormat("h:mm a");
   public static final DateFormat TIMESTAMP_FORMAT 	        = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
   public static final DateFormat FULL_TIMESTAMP_FORMAT     = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
   public static final DateFormat RANGE_FORMAT 		        = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss-HH:mm");
   public static final DateFormat GPXDATE_FORMAT 	        = new SimpleDateFormat("yyyy-MM-dd");
   public static final DateFormat GPXTIME_FORMAT 	        = new SimpleDateFormat("HH:mm:ss");
   public static final DateFormat SHORT_MDY                 = new SimpleDateFormat("MM/dd/yy");
   public static final DateFormat MDY 				        = new SimpleDateFormat("MM/dd/yyyy");
   public static final DateFormat MDYHYPHEN                 = new SimpleDateFormat("MM-DD-YYYY");
   public static final DateFormat MDY_HM  			        = new SimpleDateFormat("MM/dd/yyyy HH:mm");
   public static final DateFormat MDY_HMS                   = new SimpleDateFormat("MM/dd/yy HH:mm:ss");

   
   public static int getLastDayOfMonth(Date currDate) 
   {
       Calendar calendar = Calendar.getInstance();
       calendar.setTime(currDate);
       
       return calendar.getActualMaximum(Calendar.DATE);
   }
   
   public static Date getFirstDayOfMonth(Date currDate) 
   {
       Calendar cal = Calendar.getInstance();
       cal.setTime(currDate);
       cal.set(Calendar.DAY_OF_MONTH, cal.getActualMinimum(Calendar.DAY_OF_MONTH));
       
       return cal.getTime();    
   }
   
   public static int getDayOfMonth(Date currDate) 
   {
       Calendar calendar = Calendar.getInstance();
       calendar.setTime(currDate);
       return calendar.get(Calendar.DAY_OF_MONTH);
   }
   
   public static boolean isFirstDayOfMonth() 
   {
       return ( getDayOfMonth(new Date()) == 1 );
   }
   
   public static long getDifferenceInMinutes( Date StartTime, Date EndTIme )
   {
	   String 			 sTime 		   = fmtDate(StartTime, TIMESTAMP_FORMAT);
	   String 			 eTime 		   = fmtDate(EndTIme, TIMESTAMP_FORMAT);	   
	   DateTimeFormatter formatter     = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
	   LocalDateTime 	 dateTime1 	   = LocalDateTime.parse(eTime, formatter);
	   LocalDateTime 	 dateTime2 	   = LocalDateTime.parse(sTime, formatter);
	   long 			 diffInMinutes = java.time.Duration.between(dateTime2, dateTime1).toMinutes();
	   
	   if( diffInMinutes < 0 )
	   {
	       diffInMinutes = 0;
	   }
	   
	   return diffInMinutes;
   }
  
   public static String MintoHM(long minutes )
   {
       return LocalTime.MIN.plus( Duration.ofMinutes( minutes )).toString();
   }

   public static Date AddNumDays( Date StartTime, int numDays )
   {
	   String 		sTime        = fmtDate(StartTime, GPXDATE_FORMAT);
	   LocalDate 	parsedDate   = LocalDate.parse(sTime); 
	   LocalDate 	addedDate    = parsedDate.plusDays(numDays);   
	   Date date                 = Date.from(addedDate.atStartOfDay(ZoneId.systemDefault()).toInstant());
 
	   return date;
   }

   public static boolean isDate( DateFormat dateFormat, String dateText )
   {
       boolean  success = true;
       
       try
       {
           dateFormat.parse(dateText);
       }
       catch( Exception e)
       {  
           success = false;
       }
       
       return success;
   }
   
   public static Date getDate( DateFormat dateFormat, String dateText )
   {
	   Date date = new Date();
	   
	   try
	   {
		   date = dateFormat.parse(dateText);
	   }
	   catch( Exception e)
	   {  
	   }
	   
	   return date;
   }

   public static String fmtDate(Date date, DateFormat dateFormat)
   {    
	  String result = "";
	  
      if(date != null)
      {
    	  result =  dateFormat.format(date);
      }
      
      return result;     
   }
 
   /**
    * Format a String for HTML Display
    */
   public static String fmtForDisplay(String msg) 
   {
       if( msg.trim().isEmpty() == true ) return msg.trim();
       
       int size         = 30;
       String result    = new String();
       
       // Give the list the right capacity to start with. You could use an array
       // instead if you wanted.
       List<String> ret = new ArrayList<String>((msg.length() + size - 1) / size);

       for (int start = 0; start < msg.length(); start += size) 
       {
           ret.add(msg.substring(start, Math.min(msg.length(), start + size)));
       }
       
       for( String item : ret )
       {
           result += item + "<br>";
       }
       
       return result;  
   }


   /**
    * Prevent "null" string from being displayed.
    */
   public static String notNull(Object obj)
   {
      if (obj != null)
      {
         return obj.toString();
      }
      else
      {
         return "";
      }
   }
   
   /**
    * Prevent "null" string from being displayed 
    * return nullVal string
    */
   public static String notNull(Object obj, String nullVal )
   {
      if (obj != null)
      {
         return obj.toString();
      }
      else
      {
         return nullVal;
      }
   }
   /**
    * Formats milliseconds as a string hh:mm:ss
    */
    public static String fmtTimespan(long totalMillis)
    {
       return fmtTimespan(totalMillis, false);
    }
    
    /**
     * Formats milliseconds as a string hh:mm:ss (with fractional milliseconds if desired)
     */
     public static String fmtTimespan(long totalMillis, boolean showMillis)
     {
        long 	totalSec 	= totalMillis / 1000;
        long 	sec 		= totalSec % 60;
        long 	totalMin 	= totalSec / 60;
        long 	min 		= totalMin % 60;
        long 	hrs 		= totalMin / 60;                
        
        String retStr = preZero(hrs) + ":" + preZero(min) + ":" + preZero(sec); 
        
        if (showMillis)
        {
           retStr += "." + preZeroMillis(totalMillis % 1000);
        }
        
        return retStr;
     }
   
    /**
     * 
     */
    private static String preZero(long i)
    {
       String str = String.valueOf(i);
       
       if (i < 10)
       {
          str = "0" + str;
       }
       
       return str;
    }
    
    /**
     * 
     */
    private static String preZeroMillis(long i)
    {
       String str = String.valueOf(i);
       
       if (i < 10)
       {
          str = "00" + str;
       }
       else if (i < 100)
       {
          str = "0" + str;
       }
       
       return str;
    }
   
   /**
    * Checks to see if the String is numeric
    * 
    */
   public static boolean isNumeric(String str)
   {
      Double outVal = null;
      
      try
      {
         outVal = Double.parseDouble(str);
      }
      catch(NumberFormatException nex)
      { 
    	  outVal = null;
      }
      catch(NullPointerException nPex)
      {
    	  outVal = null;
      }
      catch(Exception ex)
      {
    	  outVal = null;
      }
      
      return (outVal != null);
   }
   
   /**
    * Returns true if string is not null and not blank-space/empty.
    */
   public static Integer getInteger(String strVal, Integer defaultVal)
   {
      Integer val = defaultVal;
      
      try
      {
         if ((strVal != null) && (strVal.trim().length() > 0))
         {
            val = Integer.valueOf(strVal);
         }
      }
      catch(Exception ex) { }
      
      return val;
   }
   
   /**
    * Returns true if string contains one of the items in the Array
    */
   public static boolean stringContainsItemFromList(String inputStr, String[] items)
   {
       for(int i =0; i < items.length; i++)
       {
           if(inputStr.contains(items[i].trim()))
           {
               return true;
           }
       }
       return false;
   }
   
   /**
    * Returns true if string contains one of the items in the Array
    */
   public static boolean compareWithoutSpace(String a, String b)
   {
       String compressedA = a.replace(" ",""); 
       String compressedB = b.replace(" ",""); 
       
       boolean result = compressedA.equalsIgnoreCase(compressedB );
       
       return result;    
   }
   
   /**
    * 
    */
   public static void CopyFiles(Path source, Path dest)
   {
       try 
       {
           if( Files.isDirectory(source) || Files.isDirectory(dest) )
           {
               return;
           }
                      
           Files.copy(source, dest, StandardCopyOption.REPLACE_EXISTING);
       } 
       catch (Exception e) 
       {
           Logger.println( "Exception Copying: " + source + " >> " + dest + " Error: " + e.getMessage() );
           
           return;
       }
   }

   /**
    * 
    */
   public static void DeleteFile(Path source)
   {
       try 
       {
           if( Files.isDirectory(source) )
           {
               return;
           }
       
           Files.delete(source);
       }
       catch (Exception e) 
       {
           Logger.println( "Exception Deleteing: " + source );
           
           return;
       }       
   }
  
}
