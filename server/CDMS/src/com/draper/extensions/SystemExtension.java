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
package com.draper.extensions;

import java.sql.*;
import java.util.Properties;

import com.draper.application.AppConfig;
import com.draper.utilities.JDBCDatabaseInerface;
import com.draper.utilities.Logger;
import com.draper.utilities.TableContainer;
import com.draper.utilities.TableView;


//---------------------------------------------------------------------------------------------------------------
//
//  Class to Load system configuration values from a spreadsheet into the system
//
//---------------------------------------------------------------------------------------------------------------     
public final class SystemExtension extends JDBCDatabaseInerface
{  
  private   Properties              mProperties     = new Properties();
  private   TableContainer          mTableData      = null;
  private   TableView               mView           = null;

  /**********************************************************************************************
   * CTOR
   * 
   */
  public SystemExtension(boolean verbose)
  { 
      Connection conn = null;

      mProperties.put("DRIVER", "org.relique.jdbc.csv.CsvDriver");
      mProperties.put("URL", "jdbc:relique:csv:" + AppConfig.storagePath);
      
	  try
	  {
		  // Open a Database connection
     
		  conn = OpenConnection( mProperties  ); 
		  	  
          // Load the data form the spreadsheet
	      
          mTableData = Query(  conn, "Select * from config" );                

          loadConfig();
		  
		  // Close the connection
		  
		  CloseConnection(conn);
		  
          if( true == verbose )
          {
              mTableData.printQueryMetaDataResults(System.out);
              mTableData.printQueryHeaderResults(System.out);
              mTableData.printQueryTableResults(System.out);
              
              // Build a Swing Table Viewer for debugging
              mView = new TableView(mTableData);
          }

	  }	  
	  catch( Exception e ) 
	  { 
          System.err.println( "ERROR: " + e ); 
          CloseConnection(conn);      
	  }    
  } 
   
  /**********************************************************************************************
   * Load the Information from a CSV
   * @return
   */
  private void loadConfig()
  {                          
      try 
      {           
          for( int i = 0; i < mTableData.getRowCount(); i++)
          {
              String[] 		 rowdata = (String[])mTableData.getRowData(i);                             
              
              mProperties.put(rowdata[0], rowdata[1]);
          }
      }
      catch (Exception e)
      {
          Logger.println(this, e);
      } 
  }
  
  /**********************************************************************************************
   * 
   * @return
   */
  public void showPanel(boolean show)
  {     
      if( mView != null)
      {
          mView.togglePanel(show);
      }
  }
}
