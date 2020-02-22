#!/bin/bash

INPUT=$1
CNT=0
sed -n -e s/__NR_/SYS_/p < $INPUT | awk '{printf "["$3"] = \"" $2 "\",\n"}' 
