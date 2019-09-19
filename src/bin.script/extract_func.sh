#!/bin/bash

if [ "$#" -ne 2 ]; then
	echo "Use ./dump_func.sh <func> <binary>"
	exit 1
fi

FUNC=$1
BIN=$2

i=`nm -S --size-sort $BIN | grep "\<$FUNC\>" | \
        awk '{print toupper($1),toupper($2)}'`
echo "$i" | while read line; do
        start=${line%% *}
        size=${line##* }
        end=`echo "obase=16; ibase=16; $start + $size" | bc -l`
        objdump -d --section=.text \
                   --start-address="0x$start" \
                   --stop-address="0x$end" $BIN
done
