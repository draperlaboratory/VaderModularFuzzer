<#
.SYNOPSIS
    A script to standup a specified number of VMF workers for use with distributed fuzzing on windows worker nodes
.DESCRIPTION
    This script will start up -number of VMF worker nodes, each node stared up with the following VMF startup command:
        
        bin/vader -d $filename
    
    See below for description of these parameters.  
.NOTES
    Author: Jesse Sullivan
    Date: 03-05-2025
#>

param(
    # The number of VMF worker nodes to setup
    [Int] $number,
    # The configuration files to use for each worker node.  This configuration file is expected to be able to support windows compatabile VMF modules.
    [string] $filename
)
Write-Output "Script will start $number VMF instances with the command ./bin/vader -d $filename";
Write-Output "All VMFs will be started silently in the background"
For ($i = 0; $i -lt $number; $i++)
{
    Start-Job -ScriptBlock { 
        param($filename, $i)
        ./bin/vader -d $filename | Out-File "fuzzer-$i.log" 
    } -ArgumentList $filename,$i
}
