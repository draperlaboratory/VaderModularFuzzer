<!-- 
   ===============================================================================
   Vader Modular Fuzzer (VMF)
   Copyright (c) 2021-2023 The Charles Stark Draper Laboratory, Inc.
   vader@draper.com
    
   Effort sponsored by the U.S. Government under Other Transaction number
   W9124P-19-9-0001 between AMTC and the Government. The U.S. Government
   Is authorized to reproduce and distribute reprints for Governmental purposes
   notwithstanding any copyright notation thereon.
    
   The views and conclusions contained herein are those of the authors and
   should not be interpreted as necessarily representing the official policies
   or endorsements, either expressed or implied, of the U.S. Government.
    
   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License version 2 (only) as 
   published by the Free Software Foundation.
    
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program. If not, see http://www.gnu.org/licenses/.
    
   @license GPL-2.0-only https://spdx.org/licenses/GPL-2.0-only.html
  ===============================================================================
-->
<%@page language="java" import="java.util.*" pageEncoding="ISO-8859-1"%>
<%@page  import="com.draper.utilities.*"%>
<%@page  import="com.draper.application.*"%>
<%
String path     = request.getContextPath();
String basePath = request.getScheme()+"://"+request.getServerName()+":"+request.getServerPort()+path+"/";
%>
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>

<meta http-equiv="X-UA-Compatible" content="IE=EmulateIE8">
<meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
<META HTTP-EQUIV="CACHE-CONTROL" CONTENT="NO-CACHE">


<base href="<%=basePath%>">

<title>CDMS<%=AppConfig.softwareVersion%></title>

<link   rel="shortcut icon" href="<%=UrlUtil.appRoot(request)%>icons/emerald.jpg">

<link   rel="stylesheet" href="<%=UrlUtil.appRoot(request)%>css/theme.css"         type="text/css">
<link   rel="stylesheet" href="<%=UrlUtil.appRoot(request)%>css/eis.css"           type="text/css">
<link   rel="stylesheet" href="<%=UrlUtil.appRoot(request)%>css/w3.css"            type="text/css">
<link   rel="stylesheet" href="<%=UrlUtil.appRoot(request)%>css/jquery-ui.min.css" type="text/css">

<script type="text/javascript" src="<%=UrlUtil.appRoot(request)%>js/jquery-latest.min.js"></script>
<script type="text/javascript" src="<%=UrlUtil.appRoot(request)%>js/jquery-ui.js"></script>
<script type="text/javascript" src="<%=UrlUtil.appRoot(request)%>js/jquery.tablesorter.min.js"></script>
<script type="text/javascript" src="<%=UrlUtil.appRoot(request)%>js/jquery.tablesorter.widgets.js"></script>
<script type="text/javascript" src="<%=UrlUtil.appRoot(request)%>js/jquery.TableCSVExport.js"></script>
<script type="text/javascript" src="<%=UrlUtil.appRoot(request)%>js/eis.js"></script>
 
<script type="text/javascript">

	 var appRoot   = "<%=UrlUtil.appRoot(request)%>";
	 var seconds   = 0;
   
     /*************************************************************************************************************************************
     *
     * Startup the system       
     *
     *************************************************************************************************************************************/
     function startup(e) 
     {            
         setInterval(tick, 2000);
         
         getClusters();     
     }
     
     /*************************************************************************************************************************************
     *
     *  Update te dynamic parts of the page
     *
     *************************************************************************************************************************************/
     function tick()
     {        
         seconds++;
         
         var clusterid = $('#SelectedId').get(0).innerHTML;
         
         if( !isEmpty(clusterid) )
         {          
             var args = "ClusterId=" + clusterid;
             
             var rslt = $.getJSON( appRoot + 'admin/Performance',args, 
            		 
             function(performanceResult)
             {    
                 // Set the system wide avail(registtered) fuzzer count
                 var element = document.getElementById('availfuzzers');       
                 if( element != null ) element.innerHTML = performanceResult.unallocFuzzerSize + " / (Total " + performanceResult.regFuzzerSize + ")";
           
                 for (var i = 0, len = performanceResult.scenarios.length; i < len; i++) 
                 {            	
                	var id      = performanceResult.scenarios[i].id;              	 
                	var kvItems = performanceResult.scenarios[i].data;
                                   	
                    var activeFuzzers = kvItems.find(item => item.key === "ACTIVE");
                                	 
                    var scenarioActiveElement = document.getElementById('ACTIVE' + id);       
                    if( scenarioActiveElement != null ) scenarioActiveElement.innerHTML = activeFuzzers.value;
                    
                    var state = kvItems.find(item => item.key === "STATE");
                    
                    scenarioActiveElement = document.getElementById('STATE' + id);       
                    if( scenarioActiveElement != null ) scenarioActiveElement.innerHTML = state.value;
                    
                    var type = kvItems.find(item => item.key === "TYPE");
                    
                    scenarioActiveElement = document.getElementById('TYPE' + id);       
                    if( scenarioActiveElement != null ) scenarioActiveElement.innerHTML = type.value;
                 }
                 
                 for (var i = 0, len = performanceResult.clusters.length; i < len; i++) 
                 {              
                     var id      = performanceResult.clusters[i].id;                
                     var kvItems = performanceResult.clusters[i].data;
                     
                     var tcSize  = kvItems.find(item => item.key === "TESTCASE");
                    
                     var clusterActiveElement = document.getElementById('TESTCASE' + id);       
                     if( clusterActiveElement != null ) clusterActiveElement.innerHTML = tcSize.value;

                     var tcSize = kvItems.find(item => item.key === "STATE");
                     
                     clusterActiveElement = document.getElementById('CSTATE' + id);       
                     if( clusterActiveElement != null ) clusterActiveElement.innerHTML = tcSize.value;
                 }
             }
             ).fail(  
            		 
             function(data) 
             {
                console.log( "error" );
             }
             
             ).always(
            		 
             function() 
             {
                console.log( "complete" );
             }
             );
         }
     }

    /*************************************************************************************************************************************
    *
    * Shutdown the system       
    *
    *************************************************************************************************************************************/
     function shutdown(event) 
     {    
    	 dialogAction(event, "admin/Shutdown", "", "Shutdown System?");         
     }

     /*************************************************************************************************************************************
     *
     * Stop all VMFs in the cluster
     *
     *************************************************************************************************************************************/
    function stopCluster(e) 
    {   
        var clusterid = $('#SelectedId').get(0).innerHTML;
                                    
        if( !isEmpty(clusterid) )
        {          
            var args = "ClusterId=" + clusterid;

            return dialogAction(e, 'admin/StopCluster', args, "Stop Cluster?" );               
        }
    }
    
    /*************************************************************************************************************************************
    *
    * Stop all VMFs in the cluster
    *
    *************************************************************************************************************************************/
    function minimizeCorpus(e, scenarioid) 
    {   
        var args = "ScenarioId=" + scenarioid;

        return dialogAction(e, 'admin/MinimizeCorpus', args, "Minimize Corpus ?" );               
    }
    /*************************************************************************************************************************************
    *
    *  Delete A Scenario
    *
    *************************************************************************************************************************************/
    function deleteScenario(e, scenarioid,name) 
    {            
       console.log(scenarioid);
       
       if( !isEmpty(scenarioid) )
       {               
           var args = "ScenarioId=" + scenarioid;

           return dialogAction(e, 'admin/DeleteScenario', args, "Delete Scenario " + name + " ?" );               
       }
    }
   
    /*************************************************************************************************************************************
     *
     * Generc Action Dialog       
     *
     *************************************************************************************************************************************/
    function dialogAction(e, queryName, args, title) 
    {               
        $( function() 
        {
            $( "#genericdialog" ).dialog(
            {
              resizable: false,
              height: "auto",
              dialogClass: 'genericDialogClass',
              width: 300,
              modal: true,
              buttons: 
              {
                YES: function() 
                {
                    $( this ).dialog( "close" );
                  
                    var rslt = $.getJSON
                                       (        appRoot + queryName, 
                                                args, 
                                                function(data)
                                                {  
                                                    return getClusters(); 
                                                }
                                       ).fail
                                       (        function() 
                                                {
                                                    console.log( "error" );
                                                }
                                       ).always
                                       (
                                                function() 
                                                {
                                                    console.log( "complete" );
                                                    
                                                }
                                       );
                },
                NO: function() 
                {
                  $( this ).dialog( "close" );
                }
              }
            });
            
            // Modify Dialog Title              
            $( "#genericdialog" ).dialog( "option", "title", title );

        });             
    }
    
	/*************************************************************************************************************************************
	 *
	 * Load of Main Page. Get the Cluster list form the server and put them into Cards for selection. 
	 * Build a Tabbed Page so we can switch between Clusters and Scenarios
	 *
	 *************************************************************************************************************************************/
	function getClusters() 
	{
	    var DataDiv                 = document.getElementById("SelectionList");        	    
	    DataDiv.innerHTML           = '';
	    var SelectionResults   	    = document.getElementById("SelectionResults");        	    
	    SelectionResults.innerHTML  = '';
    
	    var rslt = $.getJSON
   		   (
   				   	appRoot + "campaign/get/clusters",			   
					function(data)
	    			{
   				   		
   				   		for (var i = 0, len = data.length; i < len; i++) 
   				   		{
							var $element1 = $(
							[
			                  "<div style='border:1px solid white' class='w3-panel w3-hover-border-blue' id='SelectionContainer"+ data[i].clusterId + "'>",
							  "<div class='w3-card-4' id='SelectionCard" + data[i].clusterId + "' onmouseup=\"return getScenarios('" + data[i].clusterId + "')\">",
								  "<div class='w3-container w3-light-blue'>",
                                  "<table class='campaignstats w3-block w3-light-blue w3-small'>",
                                  "<tr><td></td><td></td><td></td></tr>",
                                  "<tr><td width='90%'><b><i><span id='cTITLE" + data[i].clusterId +"'>" + data[i].title  + "</span></i></b></td>",
                                  "<td>&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp</td>",
                                  "<td><a href='#' onclick='stopCluster(event);'><img class='logo' src='icons/stop.png' alt='Stop' width='12' height='12'></a></td></tr>",
                                  "</table>",
								  "</div>",
							      "<table style='width:100%'  class='campaigndates w3-block w3-light-gray w3-small'>",
							          "<tr><td></td><td></td><td></td></tr>",
							          "<tr><td><b>Created</b></td><td><b>"        + data[i].updated   + "</b></td></tr>",
							          "<tr><td><b>Corpus Size</b></td><td id='TESTCASE" + data[i].clusterId +"'>" + data[i].corpusSize  + "</td></tr>",
							      "</table>",									 
                                  "<p class='w3-small'>" + data[i].description + "<p>",                                                           
                              "</div>",
							  "</div>",
						    ].join("\n"));
							
							$("#SelectionList").append($element1);
   				   	    }

   				   		if( data.length > 0) 
   				   		{
    						var selectedCard        = $('#SelectedId').get(0);	    					    
    						selectedCard.innerHTML  = data[0].clusterId;	                  
    							
    						getScenarios(data[0].clusterId ); 
   				   		}
   				   		
   				   		return false;
	    			}
			).fail
			(		
					function() 
			  		{
				   		console.log( "error" );
			    	}
			).always
			(
			  		function() 
			  		{
			  			console.log( "complete" );			  			
			    	}
			);   
	 }
	
	 /*************************************************************************************************************************************
	 * Get a List of Scenarios given the Cluster Id from the server
	 *
	 *************************************************************************************************************************************/
	  function getScenarios(ClusterID) 
	  {	
		 var DataDiv   	             = document.getElementById("SelectionResults");        	    
		 DataDiv.innerHTML           = '';
		 var args 	  		         = 'clusterId=' + ClusterID;
		 var selectedCard            = $('#SelectedId').get(0);	    					    
		 var element 			     = document.getElementById('SelectionContainer' + selectedCard.innerHTML );
		 element.style.border        = "1px solid white";		
		 selectedCard.innerHTML      = ClusterID;	                  
		 var nextElement 		     = document.getElementById('SelectionContainer' + ClusterID);
		 nextElement.style.border    = "2px solid blue";		
		    				
		 //----------------------------------------------------------------------------------------------------------
         // Cluster File Uploading Area 

         var $ClusterFilesBanner = $("<div style='position:relative;' class='w3-panel w3-blue w3-round-large w3-medium' id='cfb'><p>Cluster Files</p></div>");
         $("#SelectionResults").append($ClusterFilesBanner);
         
         var $element1 = $("<div id='clusterDiv'></div>");                            
         $("#SelectionResults").append($element1);
         
         $('#clusterDiv').load(appRoot + "jsp/loadclusterfiles.html", function(data)
         {                                                                              
            $.getJSON( appRoot + 'admin/listcluster/' + ClusterID, function(data) { handleFileList(null,data); });
         });
                               
         //----------------------------------------------------------------------------------------------------------
         // Manage Cluster Area
         
         var $ClusterMgmtBanner= $(  "<div style='position:relative;top:40px;' class='w3-panel w3-blue w3-round-large w3-medium' id='cmb'><p>Cluster Tasking</p></div>");                                                             
         $("#SelectionResults").append($ClusterMgmtBanner);
 
         var $clusterManagment = $( "<div class='slidercontainer' id='scenariosliderdiv' style='position:relative;left:10px;top:30px'></div>");                                  
         $("#SelectionResults").append($clusterManagment);
                
         var $fuzzerManagment = $("<div id='availfuzzerdiv' style='margin:0;padding:0;position:relative;top:40px;left:10px;'>" +       
        		                  "<table><tr>" +
        		                  "<td style='font-size:12px;font-weight: bold;font-style: italic;' color='#000000' face=Verdana'>Available VMF Fuzzers:</td>"+
        		                  "<td id='availfuzzers'></td>" +
        	                      "<td>&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp</td>" +
        	                      "<td><input type='submit' class='applybutton' id='ApplyChanges' name='ApplyChanges' value='Apply Changes' " +
           	                      "onclick=\"updateCluster(event, $('#SelectedId').get(0).innerHTML);\"></td>" +
                                  "<td id='availfuzzers'></td>" +
                                  "<td>&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp</td>" +
           	                      "<td><button type='button' id='addscenariobutton' class='addscenariobutton sctooltip'>" +
           	                      "<img class='logo' id='astipimage' src='icons/addscenario.png' width='20' height='20'><span id='tipaddsc' class='sctooltiptext'>Add Scenario</span></button</td>" +
                                  "</tr></table>" +
                                  "</div>");       
         $("#SelectionResults").append($fuzzerManagment);   
         
         var $asDiv = $( "<div id='asDiv' style='position:relative;top:60px;display:none;'></div>" );                                  
         $("#SelectionResults").append($asDiv);
                  
         var output = [];
        
         // Build the sliders for selection of capacity and visual of current VMF assignments       
         var rslt = $.getJSON
         (        
              appRoot + 'campaign/get/scenarioBeans',  args, 
              function(data)
              {   
            	 if(data.length > 0)
                 {
                     output.push("<table id='scenarioslidertable'><tr><th>Type</th><th>Scenario</th><th style='width:60%'>Capacity</th><th>VMF Fuzzers</th><th>State</th><th></th></tr>" );           		 
                 }
                 for (var i = 0, len = data.length; i < len; i++) 
                 {                		
                     var capacityEl = "<td><span id='CAP" +data[i].Id +"'>" + data[i].Capacity +"</span>" +
                                      "&nbsp&nbsp&nbsp&nbsp<input id='" + data[i].Id + "' style='position:relative;' type='range' " + 
                                      "onInput=\"CAP"+data[i].Id+ ".innerText= this.value\"  min='0' max='200' value='" + data[i].Capacity + "' class='slider'></td>";

                		if( data[i].Type == "Minimizer") 
                		{
                			capacityEl = "<td><button type='button' id='minimizeCorpus' class='genericbutton' onclick='minimizeCorpus(event," + +data[i].Id +");'>Minimize</button></td>";
                		}
                		
                     output.push(
                                 "<tr><td id='TYPE" +data[i].Id +"'>" + data[i].Type + "</td>" +
                                 "<td>" + data[i].ScenarioName + "</td>" +
                                 capacityEl +
                                  "<td id='ACTIVE" +data[i].Id +"'>" + data[i].ActiveFuzzers +"</td>" +
                                 "<td id='STATE"  +data[i].Id +"'>" + data[i].State +"</td>" +
                                 "<td id='ACTION" +data[i].Id +"'>" + data[i].Action +"</td></tr>"
                                );

                 }    
                 
                 if( data.length > 0 ) 
                 {
                	 output.push("</table>");
                     document.getElementById('scenariosliderdiv').innerHTML =  output.join('');
                  }
              }
              
           ).fail( function() { console.log( "Error load scenario for manage cluster" ); });
            
           //----------------------------------------------------------------------------------------------------------
	       // Scenario Creation
		   // Setup a button so we can expand the creation of the Scenario area
                     
           var $scenarioBanner = $( "<div style='position:relative;top:40px;' class='w3-panel w3-blue w3-round-large w3-medium' id='sbanner'><p>Scenario Information</p></div>");
           $("#SelectionResults").append($scenarioBanner);
           

           //----------------------------------------------------------------------------------------------------------
           // Scenario Table Area 
         
           var $tableDiv = $( "<div id='tableDiv' style='position:relative;top:40px;display:block'></div>" );                              
           $("#SelectionResults").append($tableDiv);
           
           var rslt = $.getJSON
           (appRoot + 'campaign/get/scenarios', args, 
           function(data)
           {                                               
                 // Build the scenario table from the response of the server query
                
                 var table = $.makeTable(data, [["data", "VMF KPI(avg)"], ["VMFLink", "Name"]], ["ScenarioName","Id","Type","State","Capacity","ActiveFuzzers", "Action"] );
                 $("#tableDiv").append(table);  
                 
                 table.tablesorter({ sortList        : [[0,0]],
                                     theme           : 'jui', 
                                     headerTemplate  : '{content} {icon}', 
                                     widthFixed      : false,
                                     tabIndex        : true,
                                     dateFormat      : "mmddyyyy",
                                     sortMultiSortKey: "shiftKey",
                                     sortResetKey    : 'ctrlKey',
                                     widgets         : [ 'resizable', 'stickyHeaders', 'uitheme', 'zebra','columns'],                                                
                                     widgetOptions   : {resizable_addLastColumn: true, resizable: true, resizable_widths : [ '40%','60%'],zebra : ["even", "odd"],columns: ["primary","secondary" ] }
                                  });    
           }).fail( function() {   console.log( "error get scenarios" ); });
                                
           
           // Handle te button to add a scenario
           $('#addscenariobutton').click(function() 
           {                                    
               var x = document.getElementById("asDiv");
               
               if (x.style.display === "none") 
               { 
                    $('#asDiv').load(appRoot + "jsp/createscenario.html", function(data)
                    {                                            
                        $.getJSON( appRoot + 'admin/listcluster/' + ClusterID, function(data) { scenarioList(data); });
                    });
                
                    x.style.display     = "block";                    
                    var actooltip       = document.getElementById("tipaddsc");                  
                    actooltip.innerHTML = "Collapse";                    
                    var image           = document.getElementById("astipimage");
                    image.src           = "icons/minus.png"
               } 
               else 
               {
                    x.style.display     = "none";
                    var actooltip       = document.getElementById("tipaddsc");                  
                    actooltip.innerHTML = "Add Scenario";
                    var image           = document.getElementById("astipimage");
                    image.src           = "icons/addscenario.png"
               }
               return true;
           });
                            
            //----------------------------------------------------------------------------------------------------------
            // Setup the Corpus Display Area
        
            var $clustercorpus = $(  "<div style='position:relative;top:40px;' class='w3-panel w3-blue w3-round-large w3-medium' id='clustercorpus'><p>Corpus Data</p></div>");                                                             
            $("#SelectionResults").append($clustercorpus);

            var $corpusFilter = ("<input type='text' style='position:relative;left:165px;top:-10px;width:150px;height:18px;' value='CRASHED'id='corpusfilter' name='corpusfilter' onkeydown='getWholeCorpus(event,this)' >");
            $("#SelectionResults").append($corpusFilter);
            
            var $corpusSpan = ("<span id='corpusspan' style='position:relative;left:175px;top:-10px;width:150px;height:18px;'>Hit Enter to Search Tags</span>");
            $("#SelectionResults").append($corpusSpan);
             
            var $corpusDiv = $( "<div id='corpusDiv'></div>" );                              
            $("#SelectionResults").append($corpusDiv);                          
                               
            return false;
  	    }
	    
	    /*************************************************************************************************************************************
	     *
	     *
	     *************************************************************************************************************************************/
	    function getVMFs(ScenarioId) 
	    { 
	        var selectedCard            = $('#SelectedId').get(0);                              
	        var element                 = document.getElementById('SelectionCard' + selectedCard.innerHTML );
	        var DataDiv                 = document.getElementById("SelectionResults");              
	        DataDiv.innerHTML           = "<a href=\"javascript:getScenarios('" + selectedCard.innerHTML + "')\" style='font-size:14px;'>Go Back</a>";
	        var args                    = 'ScenarioId=' + ScenarioId;
	        
	        var rslt = $.getJSON
	                   (        appRoot + 'campaign/get/vmfs', 
	                            args, 
	                            function(data)
	                            {  
	                                var table  = $.makeTable(data,[["data", "VMF KPIs", "uid", "scenarioId", "clusterId"]]);	                                                                         
	                                table.appendTo("#SelectionResults");
	                                
	                                table.tablesorter
	                                ({ 
	                                	sortList        : [[0,0]],
                                        theme           : 'jui', 
                                        headerTemplate  : '{content} {icon}', 
                                        widthFixed      : false,
                                        tabIndex        : true,
                                        dateFormat      : "mmddyyyy",
                                        sortMultiSortKey: "shiftKey",
                                        sortResetKey    : 'ctrlKey',
                                        widgets         : [ 'resizable', 'stickyHeaders', 'uitheme', 'zebra','columns'],                                                
                                        widgetOptions   : {resizable_addLastColumn: true, resizable: true, resizable_widths : [ '25%', '15%', '15%', '25%', '20%'],zebra : ["even", "odd"],columns: ["primary","secondary" ] }
                                     });                            
	                               
	                                return false;
	                            }
	                   ).fail
	                   (        function() 
	                            {
	                                console.log( "error" );
	                            }
	                   ).always
	                   (
	                            function() 
	                            {
	                                console.log( "complete" );
	                            }
	                   );       
	     }
	      
	     
        /*************************************************************************************************************************************
        *
        *
        *************************************************************************************************************************************/
       function getWholeCorpus(event, e) 
       { 
        	var clusterId  = $('#SelectedId').get(0).innerHTML;
        	var targetDiv  = "#corpusDiv";
            var corpusspan = "#corpusspan";
                    	
            if(event.keyCode != 13) 
            {
               return false;
            }
           
            var keyword  = e.value;          
            var args     = "Tags=" + keyword;
          
            var rslt  = $.getJSON
                        (      appRoot + 'corpus/getCorpusView/' + clusterId, args,
                               function(data)
                               {  
                                   document.getElementById('corpusspan').innerHTML = data.length + " Items Returned";
                        	       
                                   var table  = $.makeTable(data, [["", ""]], ["id","scenarioId","clusterId"]);
                                   $(targetDiv).empty().append(table);  
                                  
                                   table.tablesorter
                                   ({ 
                                       sortList        : [[0,0]],
                                       theme           : 'jui', 
                                       headerTemplate  : '{content} {icon}', 
                                       widthFixed      : false,
                                       tabIndex        : true,
                                       dateFormat      : "mmddyyyy",
                                       sortMultiSortKey: "shiftKey",
                                       sortResetKey    : 'ctrlKey',
                                       widgets         : [ 'resizable', 'stickyHeaders', 'uitheme', 'zebra','columns'],                                                
                                       widgetOptions   : {resizable_addLastColumn: true, resizable: true,resizable_widths : [ '30%', '20%', '30%', '25%'], zebra : ["even", "odd"],columns: ["primary","secondary" ] }
                                    });                            
                                  
                                   
                                   return false;
                               }
                      ).fail
                      (        function() 
                               {
                                   console.log( "error" );
                               }
                      ).always
                      (
                               function() 
                               {
                                   console.log( "complete" );
                               }
                      );       
        }
	       
		/*************************************************************************************************************************************
		 *
		 * Open an overlay form for diaplying the details of a message in JSON   	
		 *
		 *************************************************************************************************************************************/
	  	function openForm(data) 
	  	{ 
	    	document.getElementById("myForm").style.display = "block";
	    	document.getElementById("formMessage").innerHTML = data;
	  	}

		/*************************************************************************************************************************************
		 *
		 * CLose the overlay form  	
		 *
		 *************************************************************************************************************************************/
	  	function closeForm() 
	  	{
	    	document.getElementById("myForm").style.display = "none";
	  	}

		  
		/*************************************************************************************************************************************
		 *
		 * Show the contents of the latest LogFile       	
		 *
		 *************************************************************************************************************************************/
	  	function showLog(result) 
	  	{ 
		  	var rslt = $.get
					   (	    appRoot + "admin/Log", 
					  			function(data)
					  	    	{  
                                    $("#" + result).val(data);
                                    $("#" + result).scrollTop( $("#" + result)[0].scrollHeight);
					  	  		}
					   ).fail
					   (		function(data) 
					  			{
						   			console.log( "error" );
	                                $("#" + result).val(data);
					    		}
					   ).always
					   (
					  			function() 
					  			{
					  				console.log( "complete" );
					    		}
					   );
	  	}
		
        /*************************************************************************************************************************************
        *
        * System Information as it is currently executing in the WebService
        *
        *************************************************************************************************************************************/
        function showInfo(result) 
        { 
           var rslt = $.get
                      (        appRoot + "admin/Info", 
                               function(data)
                               {  
                                   $("#" + result).val(data);
                               }
                      ).fail
                      (        function(data) 
                               {
                                   console.log( "error" );
                                   $("#" + result).val(data);
                               }
                      ).always
                      (
                               function() 
                               {
                                   console.log( "complete" );
                               }
                      );           
        }

        /*************************************************************************************************************************************
        *
        * Generic Loading of a html page. Sets hidden field with selected cluster Id
        *
        *************************************************************************************************************************************/
        function loadhtml(htmlPath) 
        { 
           var DataDiv         = document.getElementById("SelectionResults");              
           DataDiv.innerHTML   = '';
           var Cluster         = $('#SelectedId').get(0).innerHTML;
           
           var rslt = $.get
           (        appRoot + htmlPath, 
                    function(data)
                    {  
                        DataDiv.innerHTML = data;
                    }
           ).fail
           (        function() 
                    {
                        console.log( "error" );
                    }
           ).always
           (
                    function() 
                    {
                        console.log( "complete" );
                        
                        // The loaded page must comes with a Hidden field that we can set 
                        // and use in event calls from that page
                        
                        var regularElement = document.getElementById("ClusterId");    
                        
                        if( !isEmpty(regularElement) )
                        {               
                            regularElement.innerHTML = Cluster;
                        }

                    }
           );

        }
       
        /*************************************************************************************************************************************
        *
        * Update a Clusters information from the managecluster panel. Called on the button press           
        *
        *************************************************************************************************************************************/
        function updateCluster(e, clusterId) 
        {        	
            var CapacityList = "";
                    	
        	$('#scenarioslidertable tbody tr').each((index, tr)=> 
        	{
        	   $(tr).children('td').each ((index, td) => 
        	   {          	        	
        	       $(td).children('.slider').each( (index, element) => 
        	       {
        	           CapacityList += "," + element.id+ "," + element.value;                                          	            	
        	       });              	            
        	   }); 
            });
        	
        	CapacityList = CapacityList.substring(1); // remove leading Comma
        	        	
            var args = "ClusterId=" + clusterId + "&CapacityList=" + CapacityList;
               
            $.getJSON(appRoot + 'campaign/update/cluster', args,
                   
            function(data)
            {                               
                return false;
            }
            ).fail
            (       function() 
                    {
                        console.log( "error" );
                    }
            ).done
            (
                    function() 
                    {
                        getScenarios(clusterId);
                    }
            );
        }
       
        /*************************************************************************************************************************************
        *
        * Manage the uploading of files to the cluster for mthe local system
        * calling this with a populate FileList means you are preparing the table for wiiviewing and not hitting the selection button for new files.
        * In the case you select files they are all labeled "NEW FILE" and the upload button is enabled
        *
        *************************************************************************************************************************************/
        function handleFileList(evt, fileList) 
        {
             var output = [];
        	 var files  = null;
        	 var source = "";
        	 
        	 if( fileList == null)
             {
	            files  = evt.target.files; 
	            source = "NEW FILE"
	                
	            var x = document.getElementById("uploadbutton");
	            x.disabled = false;
	         }
        	 else
             {
        	    files  = fileList;
                source = "ON SERVER";
                var x = document.getElementById("uploadbutton");
                x.disabled = true;          		 
             }
        	 	         
	         output.push("<table id='clusterfilestable' style='width:70%'><tr><th>Name</th><th>Type</th><th>Size</th><th>Source</th></tr>");
	         	         	         
	         for (var i = 0, f; f = files[i]; i++) 
	         {
	           output.push("<tr><td>" + escape(f.name) + "</td><td>" + (f.type || "n/a") + "</td><td>" + f.size + " bytes</td><td>"+source+"</td></tr>");
	         }
	         
	         output.push("</table>");
	         	         
	         document.getElementById('fileTable').innerHTML =  output.join('');
        }        
     
        /*************************************************************************************************************************************
        *
        * Push files to the Server
        *
        *************************************************************************************************************************************/
        async function uploadClusterFiles(event, clusterId) 
        {
            event.preventDefault();
            
        	var myform   = document.getElementById("clusterform");     	  
        	var formData = new FormData(myform);

        	let response = await fetch(appRoot + "admin/upload/" + clusterId , {method: "POST", body: formData });

            if (response.status === 200) 
            {
                $.getJSON( appRoot + 'admin/listcluster/' + clusterId, function(data) { handleFileList(null,data); });
            }
        	
        }
 
 		 /*************************************************************************************************************************************
		 *
		 *  Save a new Cluster to the Server 	
		 *
		 *************************************************************************************************************************************/
		 function newCluster(e, title, description) 
		 {	
			 
            if(isEmpty(title))
            {
               console.log("Empty Cluster Title");
               return;
            }
            
            var max_title = 25;
            var max_desc  = 50;
            
            if(title.length > max_title) 
            {
            	title = title.substr(0, max_title);
            }
            
            if( !isEmpty(description) )
            {
                if(description.length > max_desc) 
                {
                	description = description.substr(0, max_desc);
                }         	
            }
            	           	
            var args = "Title=" + title + "&Description=" + description;
	        
	        
		 	$.getJSON(appRoot + 'campaign/create/cluster', args,
		 		
		 	    function(data)
		 	    {  					 			
		 			getClusters();
		 			
		 			return false;
		 	    });	   
		 	
		 	
		 	return false;
		 }
	    
        /*************************************************************************************************************************************
        *
        * Populate Scenario File Selection. THis is all Server side we just display the servers data from the cluster
        *
        *************************************************************************************************************************************/
        function scenarioList(fileList) 
        {
             var output = [];
             var files  = fileList;
              
             output.push("<div><input type='text' id='search' name='search' onkeydown='filterScenarioList(event,this)' ></div>");
             
             output.push("<select name='clusterFiles' id='clusterFiles' multiple size='30' style='height:100%;width:100%'>");
                                     
             for (var i = 0, f; f = files[i]; i++) 
             {
               output.push("<option value ='" + escape(f.name) + "'>"+ escape(f.name) +"</option>");
             }
             
             output.push("</select>");
                         
             document.getElementById('ScenarioConfigList').innerHTML =  output.join('');
             document.getElementById('ScenarioSeedList').innerHTML   =  output.join('');
        }        
		 /*************************************************************************************************************************************
         *
         *  Save a new Scenario to the Server.. TBD: Add Filter button   
         *
         *************************************************************************************************************************************/
         function newScenario(e, title, clusterid, configs, seeds, type ) 
         {  			            
			if(isEmpty(title))
            {
			    return;
            }

			var args = "Title=" + title + "&ClusterId=" + clusterid + "&Configs=" + configs + "&Seeds=" + seeds+ "&Type=" + type;

			// Submit Scenario for creaton to Server
			
            $.getJSON(appRoot + 'campaign/create/scenario', args,
                
                function(data)
                {  
                    getScenarios(clusterid);
                    
                    return false;
                });    
            
            
            return false;
         }

		 /*************************************************************************************************************************************
         *
         * Filter the list shown to the user base on their criteria  
         *
         *************************************************************************************************************************************/
        function filterScenarioList(event, e) 
        {
             if(event.keyCode != 13) 
             {
            	return false;
             }
            
             var elem     = e.parentElement.parentElement; // Parent of serach is Div, parent of tha is the differnt lists for Config or Seed             
             var select   = elem.childNodes[1]; // Select Element is second child. This sis the list of items             
             var keyword  = e.value;
             var strToken = keyword.split(";");
             var options  = [];
                        
             for (var i = 0; i < select.options.length; i++) 
             {
                 var txt = select.options[i].text;
                 options.push(txt);
             }
             
             for (var j = 0; j < options.length; j++) 
             {
            	 select.options[j].setAttribute("hidden", "hidden");   
             }
             
             for( var i = 0; i < strToken.length; i++)
             {         	 
                 for (var j = 0; j < options.length; j++) 
                 {
	                 if (options[j].toLowerCase().includes( strToken[i].toLowerCase() )) 
	                 {
	                	 select.options[j].removeAttribute("hidden");
	               	 }
                 }
             } 
             
             for (var j = 0; j < options.length; j++) 
             {
            	 select.options[j].selected=false;
             }

        }
        /*************************************************************************************************************************************
        *
        *  Get a corpus test case form the server to save locallt
        *
        *************************************************************************************************************************************/
        function downloadCorpusFile(scenarioid, clusterid, filename ) 
        {              
        	
        	var uri = "cluster" + clusterid + "/scenario"  + scenarioid + "/" + filename;
        	
            var rslt = $.get
            (        appRoot + "corpus/corpusfile/" + uri, 
                     function(data)
                     {  
                         var fileContent = data;
                         var bb          = new Blob([fileContent ], { type: 'application/octet-stream' });
                         var a           = document.createElement('a');
                         a.download      = filename;
                         a.href          = window.URL.createObjectURL(bb);
                         a.click();
                         a.remove();
                     }
            ).fail
            (        function() 
                     {
                         console.log( "error" );
                     }
            ).always
            (
                     function() 
                     {
                         console.log( "complete" );
                     }
            );
        }
		/*************************************************************************************************************************************
		 *
		 *  Save to CSV	to a file from the server
		 *
		 *************************************************************************************************************************************/
	     function exporttocsv() 
	     {	    	  
	    	  $('#corpusDiv').TableCSVExport({
	    		  separator:',',
	    		  header: [],
	    		  columns: [],
	    		  extraHeader:"",
	    		  extraData: [],
	    		  insertBefore:"",
	    		  delivery:'download' /* popup, value, download */,
	    		  emptyValue:'',
	    		  showHiddenRows:false,
	    		  rowFilter:"",
	    		  filename:"download.csv"
	    		});
		 } 
	
</script>

</head>

<body onload="startup(this)">

<p hidden id="SelectedId"></p>

<div id="Campaign" class="split left">
	<div id="container">
		<div id="top_div">
			<div class="icon-bar">
				<ul>				
				 <li><a class="tooltip" href="#home" onclick="getClusters();"> <img class="logo" src="icons/home.png" alt="Home" width="25" height="25"><span class="tooltiptext">  Home</span></a></li>
				 <li><a class="tooltip" href="#home" onclick="loadhtml('jsp/createcluster.html');"> <img class="logo" src="icons/newItem.png" alt="Add Cluster" width="25" height="25"><span class="tooltiptext">Add&nbspCluster</span></a></li>
				 <li><a class="tooltip" href="#home" onclick="shutdown(event);"><img class="logo" src="icons/shutdown.png"  alt="Shutdown"    width="25" height="25"><span class="tooltiptext">Shutdown</span></a></li>
				 <li><a class="tooltip" href="#home" onclick="exporttocsv();"> <img class="logo" src="icons/export.png"    alt="Export"      width="25" height="25"><span class="tooltiptext">Export</span></a></li>
		 		 <li><a class="tooltip" href="#home" onclick="loadhtml('jsp/settings.html');"><img class="logo" src="icons/settings.png"  alt="Settings"  width="25" height="25"><span class="tooltiptext">Settings</span></a></li>
				</ul>				
			</div>	
		</div>	
		
		<div id="bottom_div"><div id="SelectionList"></div></div>    
	</div>
</div>

<div id="SelectionResults" class="split right"></div>

<div class="form-popup" id="myForm">
  <form class="form-container">
    <div id="formMessage"></div>
    <button type="button" class="savebutton" onclick="closeForm()">Close</button>
  </form>
</div>

<div id="genericdialog"></div>

</body>
</html>