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

import java.io.*;
import java.util.*;
import java.sql.*;

//---------------------------------------------------------------------------------------------------------------
//
//  Abstract Base class to be extended. Has all the 
//  Generic API methods to open/close and execute queries on a database.
//
//---------------------------------------------------------------------------------------------------------------     
public abstract class JDBCDatabaseInerface
{
    private Properties mProperties = null;

    //---------------------------------------------------------------------------------------------------------------
    //
    // Generic SQL Update( INSERT/UPDATE/DELETE ) and returns row count effected
    //
    //---------------------------------------------------------------------------------------------------------------
    public int Update(PreparedStatement stmt)
    {
        int rowCount = 0;

        try
        {
            rowCount = stmt.executeUpdate();
        }
        catch (SQLException e)
        {
            System.err.println("Error executing Update for SQL statement: " + e);
        }
        finally
        {
            // Close the the statement

            if (stmt != null)
            {
                try
                {
                    stmt.close();
                }
                catch (Exception e)
                {
                    System.err.println("stmt.close()");
                }
            }
        }

        return rowCount;
    }

    //---------------------------------------------------------------------------------------------------------------
    //
    // Generic SQL Update( INSERT/UPDATE/DELETE ) and returns row count effected.
    // Builds statement internally.
    //
    //---------------------------------------------------------------------------------------------------------------
    public int Update(Connection conn, String sql)
    { 
        PreparedStatement stmt = null;
        
        try
        {
            stmt = conn.prepareStatement(sql);
        }
        catch (SQLException e)
        {
            System.err.println("Error Creating SQL statement: " + e);
        }
        
        return Update( stmt );
    }
    
    //---------------------------------------------------------------------------------------------------------------
    //
    // Generic SQL Query and Result Set Generation using a PreparedStatement
    //
    //---------------------------------------------------------------------------------------------------------------
    public TableContainer Query(PreparedStatement stmt) throws Exception
    {
        ResultSet       rs     = null;
        TableContainer  tc     = null;

        // Execute the query and check if result set returned
        try
        {
            rs      = stmt.executeQuery();
            tc      = new TableContainer(rs); 
        }
        catch (SQLException e)
        {
            System.err.println("Error executing Query for SQL statement: " + e);
        }
        finally
        {
            // Close the result set and the statement

            if (rs != null)
            {
                try
                {
                    rs.close();
                }
                catch (Exception e)
                {
                    System.err.println("rs.close()");
                }
            }
            if (stmt != null)
            {
                try
                {
                    stmt.close();
                }
                catch (Exception e)
                {
                    System.err.println("stmt.close()");
                }
            }
        }

        return (tc);
    }

    // ---------------------------------------------------------------------------------------------------------------
    //
    // Generic SQL Query and Result Set Generation using a Query String
    //
    // ---------------------------------------------------------------------------------------------------------------
    public TableContainer Query(Connection conn, String sql) throws Exception
    {
        ResultSet       rs      = null;
        Statement       stmt    = null;
        TableContainer  tc      = null;
        
        // Execute the query and check if result set returned
        try
        {
            stmt    = conn.createStatement();
            rs      = stmt.executeQuery(sql);           
            tc      = new TableContainer(rs); 
         }
        catch (SQLException e)
        {
            System.err.println("Error executing Query for SQL statement: " + e);
        }
        finally
        {
            // Close the result set and the statement

            if (rs != null)
            {
                try
                {
                    rs.close();
                }
                catch (Exception e)
                {
                    System.err.println("rs.close()");
                }
            }
            if (stmt != null)
            {
                try
                {
                    stmt.close();
                }
                catch (Exception e)
                {
                    System.err.println("stmt.close()");
                }
            }
        }

        return(tc);
    }

    // ---------------------------------------------------------------------------------------------------------------
    //
    // CLoses a database connection
    //
    // ---------------------------------------------------------------------------------------------------------------
    public void CloseConnection(Connection db)
    {
        // Close database connection

        if (db != null)
        {
            try
            {
                db.close();
                db = null;
            }
            catch (Exception e)
            {
            }
        }
    }

    // ---------------------------------------------------------------------------------------------------------------
    //
    // Get a Database Connection using parameters in the configuration files
    //
    // ---------------------------------------------------------------------------------------------------------------
    public Connection OpenConnection(Properties properties) throws Exception, Error
    {           
        Connection conn = null;
        mProperties     = properties;
        
        try
        {
            // Load the driver manager class into the JVM

            Class.forName( (String)mProperties.get("DRIVER") );

            // Make the connection to the database

            conn = DriverManager.getConnection( ((String)mProperties.get("URL")).trim(), mProperties);                
        }

        catch (SQLException e)
        {
            System.err.println("SQL Exception: ");

            SQLException ex = e;

            while (ex != null)
            {
                System.err.println(ex.toString());
                ex = ex.getNextException();
            }
        }

        return conn;
    }

    // ---------------------------------------------------------------------------------------------------------------
    // Reporting Configuration
    // ---------------------------------------------------------------------------------------------------------------
    protected void ReportConfig()
    {
        Enumeration<Object> theKeys = mProperties.keys();
        
        System.err.println("\n<<<Configuration settings>>>\n");

        while (theKeys.hasMoreElements())
        {
            String Key = (String) theKeys.nextElement();

            System.err.println("\t"+ Key + " = " + mProperties.getProperty(Key) + "\n" );
        }
    }
    
    // ---------------------------------------------------------------------------------------------------------------
    // Reporting Configuration
    // ---------------------------------------------------------------------------------------------------------------
    protected void DatabaseProperties(OutputStream pout) throws Exception
    {
        StringBuffer buffer = new StringBuffer(); 

        try
        {    
            Driver driver             = DriverManager.getDriver(((String)mProperties.get("URL")).trim());              
            DriverPropertyInfo[] info = driver.getPropertyInfo(((String)mProperties.get("URL")).trim(), null);
              
            for (int i = 0; i < info.length; i++) 
            {
                buffer.append(info[i].name + "\n");      // Is property value required?
                buffer.append(info[i].required + "\n");  // Get current value
                buffer.append(info[i].value + "\n");     // Get description of property
                buffer.append(info[i].description + "\n");
               
                // Get possible choices for property; 
                 
                String[] choices = info[i].choices; 
                 
                if (choices != null) 
                { 
                    for(int c = 0; c < choices.length; c++) 
                    {
                        buffer.append(choices[c] + "\n"); 
                    } 
                } 
            }
            
            for( int i =0; i < buffer.length(); i++ )
            {
                pout.write( buffer.charAt(i) ); 
            }
        }
        catch (SQLException e)
        {
            System.err.println("SQL Exception: " + e);
        }
    }
}
