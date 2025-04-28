/* =============================================================================
 * Vader Modular Fuzzer (VMF)
 * Copyright (c) 2021-2025 The Charles Stark Draper Laboratory, Inc.
 * <vader@draper.com>
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

/*--------------------------------------------------*/
/* Strip off filename from path
 */   
  
function fileStrip()
{
   var fullPath = $("#file").val();
   
   var filename = fullPath.split('\\').pop();
   
   filename = filename.substring(0, filename.lastIndexOf('.'));
    
   $("#file").val('');
   
   $("#Filename").val(filename);
       
   return false;
}
    
/*--------------------------------------------------*/
/* Check for a Null or undefined variable
 * return true if it it is null, empty or undefined
 */
function isEmpty(value)
{
  if(value == null) return true;
    
  return(value === "");
}

/*--------------------------------------------------*/
/* Pull the Parameter value off the URL
 * 
 */
function getParameterByName(name, url) 
{
	    if (!url) url = window.location.href;
	    name = name.replace(/[\[\]]/g, '\\$&');
	    var regex = new RegExp('[?&]' + name + '(=([^&#]*)|&|#|$)'), 
	    results = regex.exec(url);
	    if (!results) return null;
	    if (!results[2]) return '';
	    return decodeURIComponent(results[2].replace(/\+/g, ' '));
}
  
/*--------------------------------------------------*/
/* Dump a JSON String in a formatted Result */
function dump(arr,level) 
{
    var dumped_text = "";

    if(!level) level = 0;

    //The padding given at the beginning of the line.

    var level_padding = "";

    for(var j=0; j<level; j++) level_padding += "  ";

    if(typeof(arr) == 'object') 
    {
        for(var item in arr) 
        {
            var value = arr[item];

            if(typeof(value) == 'object') 
            { 
                dumped_text += dump(value,level+1);
                dumped_text += "\n";
            } 
            else 
            {
                dumped_text += level_padding + value;
            }
        }
    } 
    else 
    { 
        dumped_text = "===>"+arr+"<===("+typeof(arr)+")";
    }
    return dumped_text;
}   

/*--------------------------------------------------*/
/* Build a Table from the JSON Array of Objects     */
$.makeTable = function (mydata,alias,ignorecolumns) 
{
    if(!alias) alias                 = [["",""]];
    if(!ignorecolumns) ignorecolumns = [""];

    var table     = $('<table id=cdmstable class=tablesorter>');
    var tblHeader = "<thead><tr>";
    var ignore    = false;
    
    for (var k in mydata[0]) 
    {
        ignore = false;
        
        ignorecolumns.forEach(function (item, index) 
        {            
            if(  item == k )
            {
                ignore = true;
            }
 
        });

        if(ignore == false)
        {
            var headerTitle = k;
            
            alias.forEach(function (item, indx) 
            {   
                if(  k == item[0] )
                {
                    headerTitle = item[1];
                }
            });   
               
      	    tblHeader += "<th>" + headerTitle + "</th>";             
	    }
    }

    tblHeader += "</tr></thead><tbody>";

    $(tblHeader).appendTo(table);
    
    $.each(mydata, function (index, value) 
    {
        var TableRow = "<tr>";
        ignroe       = false;
        
        $.each(value, function (key, val) 
        {       
            ignore = false;
                	
            ignorecolumns.forEach(function(item, indx) 
            {
               if(  item == key )
                {
                    ignore = true;
                }
     
            });
            
            if( ignore == false )
        	{
            	if(key == "data" )
            	{   
              	   var insTable = addTable(val, $(TableRow), key, key);
            		
             	   TableRow += "<td><div>" + $( insTable[0] )[0].outerHTML + "<div></td>";                		        		
            	}            	          	
            	else
            	{
            		TableRow += "<td>" + val + "</td>";   
              	}      
            }   	 
        });
        
        TableRow += "</tr>";
        $(table).append(TableRow);
    });
    
    $(table).append("</tbody></table>")

    return ($(table));
};

//--------------------------------------------
// Add a table and tables of Tables to a container

function addTable(list, appendObj,tableClass,tableId)
{
 var table  = document.createElement("table");  
	 
 table.setAttribute("id", tableId);
 
 table.className   			  = tableClass;
 var header       		      = table.createTHead();
 
 var tableHead$ = $(header);
 var table$     = $(table);        
 var columns    = addAllColumnHeaders(list, tableHead$);
 
 for (var i = 0; i < list.length; i++)
 {
     var row$ = $('<tr/>');
     
     for (var colIndex = 0; colIndex < columns.length; colIndex++) 
     {
         var cellValue = list[i][columns[colIndex]];

         if (cellValue == null) 
         {
             cellValue = "";
         }

         if (cellValue.constructor === Array)
         {
             $a = $('<td/>');
             row$.append($a);
             
             addTable(cellValue, $a);

         } 
         else if (cellValue.constructor === Object)
         {
            var array = $.map(cellValue, function (value, index) { return [value]; });

             $a = $('<td/>');
             
             row$.append($a);
             
             addObject(array, $a);
         } 
         else 
         {
             row$.append($('<td/>').html(cellValue));
         }
     }
     
     table$.append(row$);
     
 }
 
 appendObj.append(table$);
 
 return table$;
}

/*************************************************************************************************************************************
 *
*************************************************************************************************************************************/

function addObject(list, appendObj) 
{
  for (var i = 0; i < list.length; i++) 
  {
     var row$ = $('<tr/>');

     var cellValue = list[i];

     if (cellValue == null) 
     {
         cellValue = "";
     }

     if (cellValue.constructor === Array)
     {
         $a = $('<td/>');
         row$.append($a);
         addTable(cellValue, $a);

     } 
     else if (cellValue.constructor === Object)
     {
         var array = $.map(cellValue, function (value, index) { return [value];});

         $a = $('<td/>');
         row$.append($a);
         addObject(array, $a);

     } 
     else 
     {
         row$.append($('<td/>').html(cellValue));
     }
     
     appendObj.append(row$);
  }
}

/*************************************************************************************************************************************
* Adds a header row to the table and returns the set of columns.
* Need to do union of keys from all records as some records may not contain
* all records
*************************************************************************************************************************************/
function addAllColumnHeaders(list, appendObj)
{
 var columnSet = [];
 var headerTr$ = $('<tr/>');
 
 for (var i = 0; i < list.length; i++) 
 {
     var rowHash = list[i];
     
     for (var key in rowHash) 
     {
         if ($.inArray(key, columnSet) == -1) 
         {
             columnSet.push(key);
             headerTr$.append($('<th/>').html(key));
         }
     }
 }
      
 appendObj.append(headerTr$);

 return columnSet;
}
