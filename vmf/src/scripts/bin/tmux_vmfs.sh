#!/bin/bash
while getopts n:f: flag
do
    case "${flag}" in
        n) number=${OPTARG};;
        f) filename=${OPTARG};;
    esac
done
tmux new-session -d -s vader-fuzz
echo "Script will start $number VMF instances with the command ./bin/vader -d $filename";
echo "These will be run under the tmux sesson vader-fuzz";
echo "Run the following command to view the console output for each vmf";
echo "   tmux attach -t vader-fuzz";
for i in $(seq 1 $number ); 
    do 
    echo "Spawning fuzzing job $i"
    tmux new-window -n "job_$i" -t vader-fuzz "./bin/vader -d $filename"
done
echo "All VMFs started"