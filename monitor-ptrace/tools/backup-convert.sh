#!/bin/bash
#awk 'BEGIN{
#	for(i=0; i<=10; i++) {
#		print "["i"] = ";
#	}
#}'
#sed -n -e s/__NR_/SYS_/p < syscall.h.in > 1.txt
#awk '{printf "{\""$2"\"}" "\n"}' syscall.h.in > 1.txt
#awk 'BEGIN{a1="["}{a2="]"}{printf("%s%d%s%s\n",a1,$line,a2,$1);}' 1.txt

INPUT=$1
CNT=0
#sed -n -e s/__NR_/SYS_/p < syscall.h.in | 
sed -n -e s/__NR_/SYS_/p < $INPUT | 
awk '{printf "{\""$2"\"}," "\n"}' | 
while read line; do
	echo "[$CNT] = "$line;
	let CNT+=1;
done
