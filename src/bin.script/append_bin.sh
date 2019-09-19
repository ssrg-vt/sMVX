#!/bin/bash

if [ "$#" -ne 2 ]; then
	echo "Use ./append_bin.sh <BIN patch file> <vanilla binary>"
	exit 1
fi

PATCH=$1
BIN=$2

objcopy --add-section .mvx=$PATCH --set-section-flags .mvx=load,code $BIN $BIN.mvx
