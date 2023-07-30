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

import java.util.*;
import java.sql.*;
import java.io.*;

//---------------------------------------------------------------------------------------------------------------
//
//  Class TableData
//
//---------------------------------------------------------------------------------------------------------------     
public class TableContainer
{
  
  private         int                    NotNullable         =  0;
  private         int                    Nullable            =  1;
  private         int                    column_count        =  0;
  private         int                    row_count           =  0; 
  private         List<Object[]>         AllRows             =  null;                   
  private         boolean                modified            =  false;
  private         String[]               column_names;
  private         String[]               column_type_name;
  private         int[]                  nullable;
  private         int[]                  column_type;    
 
  //---------------------------------------------------------------------------------------------------------------
  //
  //  CTOR. Pack the Result Set into a two-dimensional Array along with table MetaData.
  //
  //---------------------------------------------------------------------------------------------------------------     
  public TableContainer( ResultSet data)
  {
      setMetaData(data);
  
      AllRows   = new Vector<Object[]>();
      
      try
      {
          while ( data.next() )
          {
              Object[] rowData      = new String[column_count];
              boolean  rowIsBlank   = true;
              
              for( int x = 0; x < column_count; x++ )
              {
                  String cellValue = data.getString( x+1 );                 
                  rowIsBlank       = rowIsBlank && cellValue.trim().isBlank();           
                  rowData[ x ]     = cellValue.strip();
              }
            
              if(!rowIsBlank)
              {
                  AllRows.add(rowData);
              }
          }    
      }
      catch( Exception e )
      { 
          System.err.println("Exception: " + e); 
      }
      
      row_count = AllRows.size();
  }
 
      
  //---------------------------------------------------------------------------------------------------------------
  //
  //    Method for extracting and storing meta-data
  //
  //---------------------------------------------------------------------------------------------------------------     
  private void setMetaData( ResultSet data)
  {	
    try 
    { 
          column_count       =   data.getMetaData().getColumnCount();
          column_type        =   new int[column_count];
          column_names       =   new String[column_count];
          column_type_name   =   new String[column_count];
          nullable           =   new int[column_count];
    }
    catch( Exception e )
    {   
        System.err.println("Exception: " + e); 
    }
	
    try
    {
        for ( int x = 0; x < column_count; x++ )
        {
              column_type      [x]  =  data.getMetaData().getColumnType(x+1); 
              column_type_name [x]  =  data.getMetaData().getColumnTypeName(x+1);
              column_names     [x]  =  data.getMetaData().getColumnName(x+1).replaceAll("[^a-zA-Z0-9]","");		
              column_names     [x]  =  column_names[x].strip(); 
              
              if ( data.getMetaData().isNullable( x+1 ) == ResultSetMetaData.columnNullable )
              {
                  nullable [x]  =  Nullable;
              }
              else
              {
                  nullable [x]  =  NotNullable;
              }
        }
    }
    catch( Exception e )
    { 
        System.err.println("Exception: " + e);
    }
  }
  
  //---------------------------------------------------------------------------------------------------------------
  //
  //---------------------------------------------------------------------------------------------------------------      
  public Object getCellData(int row, String ColumnName)
  {   
    Object[] rowData = getRowData(row);

    for( int i = 0; i < column_count; i++ )
    {
        if( column_names[i].equalsIgnoreCase(ColumnName))
        {
            return rowData[i];
        }
    }
    
    return null;
  }

  //---------------------------------------------------------------------------------------------------------------
  //
  //---------------------------------------------------------------------------------------------------------------      
  public Object getCellData(int row, int col)
  {
      Object[] rowData = getRowData(row);
      
      return rowData[col];
  }

  //---------------------------------------------------------------------------------------------------------------
  //
  //   Get entire Row of Data
  //
  //---------------------------------------------------------------------------------------------------------------     
  public Object[] getRowData(int row)
  {    
    return (Object[])AllRows.get(row);
  }

  //---------------------------------------------------------------------------------------------------------------
  //
  //   Get All Rows
  //
  //---------------------------------------------------------------------------------------------------------------     
  public  List<Object[]> getAllRows()
  {    
    return AllRows;
  }

  //---------------------------------------------------------------------------------------------------------------
  // Pull column data from 
  //---------------------------------------------------------------------------------------------------------------      
  public Object[] getColumnData(int col)
  {
      String[] colData = new String[row_count];
      
      for( int i = 0; i < row_count; i++ )
      {  
          Object[] rowData  = getRowData(i);         
          colData[i]        = (String)rowData[col];
      }
      
      return colData;
  }
  
  //---------------------------------------------------------------------------------------------------------------
  //
  //---------------------------------------------------------------------------------------------------------------      
  public String[] getColumnNames()
  {
    return column_names;
  }

  //---------------------------------------------------------------------------------------------------------------
  //
  //---------------------------------------------------------------------------------------------------------------      
  public int[] getDataTypes()
  {
    return column_type;
  }

  //---------------------------------------------------------------------------------------------------------------
  //
  //---------------------------------------------------------------------------------------------------------------      
  public String[] getDataTypeNames()
  {
    return column_type_name;
  }
 
  //---------------------------------------------------------------------------------------------------------------
  //
  //---------------------------------------------------------------------------------------------------------------      
  public String getDataTypeForColumn(int column)
  {
    return column_type_name[column];
  }
 
  //---------------------------------------------------------------------------------------------------------------
  //
  //---------------------------------------------------------------------------------------------------------------      
  public int[] getColumnsNullable()
  {
    return nullable;
  }
      

  //---------------------------------------------------------------------------------------------------------------
  // setModified()  
  //---------------------------------------------------------------------------------------------------------------
  public void setModified(boolean modified)
  {
      this.modified = modified;
  }
  
  //---------------------------------------------------------------------------------------------------------------
  // isModified()  
  //---------------------------------------------------------------------------------------------------------------
  public boolean isModified()
  {
      return modified;
  }
 
  //---------------------------------------------------------------------------------------------------------------
  // getRowCount()  
  //---------------------------------------------------------------------------------------------------------------
  public int getRowCount()
  {
      return this.row_count;
  }
  
  //---------------------------------------------------------------------------------------------------------------
  // getColumnCount()  
  //---------------------------------------------------------------------------------------------------------------
  public int getColumnCount()
  {
      return this.column_count;
  }
    
  //---------------------------------------------------------------------------------------------------------------
  // printQueryMetaDataResults()  
  //---------------------------------------------------------------------------------------------------------------
  public void printQueryMetaDataResults( OutputStream pout ) throws Exception
  {   
    StringBuffer   buffer             =  new StringBuffer(); 
    String[]       columns            =  getColumnNames(); 
    String[]       column_type_names  =  getDataTypeNames();   
    int[]          data_types         =  getDataTypes(); 
    int[]          nullable           =  getColumnsNullable(); 
      
      
    buffer.append("\nQUERY RESULT SET CONTAINS " + columns.length + " COLUMNS:\n"); 

    //print metadata
    
    for( int i = 0; i < columns.length; i++ )
    { 
          buffer.append("   COLUMN NAME = " + columns[i] + "\n"); 
          buffer.append("   COLUMN TYPE = " + data_types[i] + "\n"); 
          buffer.append("   DBMS TYPE   = " + column_type_names[i] + "\n"); 
          buffer.append("   Is Nullable ? " + nullable[i] + "\n"); 
    } 
      
    buffer.append("\n"); 
    
    for( int i =0; i < buffer.length(); i++ )
    {
        pout.write( buffer.charAt(i) ); 
    }
  }  
 
  //---------------------------------------------------------------------------------------------------------------
  // printQueryHeaderResults()  
  //---------------------------------------------------------------------------------------------------------------
  public void printQueryHeaderResults( OutputStream pout ) throws Exception
  {      
     String[] columns = getColumnNames(); 
     
     pout.write(new String("\n[").getBytes() ); 
     
     for(int i = 0; i < columns.length; i++)
     { 
         pout.write( columns[i].getBytes() ); 
         
         if ( (columns.length > 1) && (i != columns.length - 1) )
         {
             pout.write( new String(",").getBytes() ); 
         }
     } 

     pout.write( new String("]\n\n").getBytes() ); 
  } 

  //---------------------------------------------------------------------------------------------------------------
  //printQueryTableResults()  
  //---------------------------------------------------------------------------------------------------------------
  public void printQueryTableResults( OutputStream pout ) throws Exception
  {  
      for(int row=0; row < row_count; row++)
      { 
          Object[] rowData = getRowData(row);
          
          printQueryResult(rowData, pout );
      } 
   
      pout.write(new String("\n").getBytes() ); 
  } 

  //---------------------------------------------------------------------------------------------------------------
  // printQueryResult()  
  //---------------------------------------------------------------------------------------------------------------
  private void printQueryResult( Object[] data, OutputStream pout ) throws Exception
  { 
      for( int col = 0; col < column_count; col++)
      { 
          if( ((String)data[col]) == null )
          {
                pout.write( new String("NULL").getBytes() );
          }
          else if( ((String)data[col]).equals("") )
          {
                pout.write( new String(" ").getBytes() );
          }
          else
          {
                pout.write( ((String)data[col]).getBytes() ); 
          }
          if( (col != (column_count-1) ) ) 
          {
                pout.write( new String(",").getBytes() ); 
          }
          else
          {
              pout.write( new String("\n").getBytes() );
          }
      } 
  }
}

