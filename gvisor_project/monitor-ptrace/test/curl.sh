#!/bin/bash
CNT=0
while [ $CNT -lt 100 ];do
	curl -s localhost:8889/index.html -o /dev/null
	if [ $? -eq 0 ];then
		echo "Success loop " $CNT
	else
		echo "Failed loop " $CNT
		break
	fi
	let CNT=CNT+1
done
