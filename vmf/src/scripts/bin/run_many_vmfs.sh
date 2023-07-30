#!/bin/bash
while getopts n:f: flag
do
    case "${flag}" in
        n) number=${OPTARG};;
        f) filename=${OPTARG};;
    esac
done
echo "Script will start $number VMF instances with the command ./bin/vader -d $filename";
echo "All VMFs will be started silently in the background"
for i in $(seq 1 $number ); 
    do exec ./bin/vader -d $filename &
done
