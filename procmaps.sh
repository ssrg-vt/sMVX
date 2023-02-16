#!/bin/bash

pids=$(pidof $1)
if [ $# != 1 ]
then
    echo "Use: ./procmaps.sh <bin>"
    exit 1
fi
echo $pids $#
for pid in $pids
do
    echo "Pid:" $pid
    cat /proc/$pid/maps
    echo
done