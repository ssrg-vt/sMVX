#!/bin/bash
### We should print .text .data .bss [addr, size]
#echo "Use:     (sudo) ./checker.sh binary "

bin=$1
rm -rf /tmp/dec.info

echo "Create /tmp/dec.info file ..."
tmpfile=$(tempfile -n /tmp/dec.info) || exit
echo "File" $tmpfile "created"

## Not familiar w/ shell script, cannot find bug in the following code
#sections=(" .text" " .data" ".bss")
#function dump_location() {
#	for i in $sections;
#		do
#			result=$(readelf -SW $bin | grep $i | python elf-section.py)
#			echo $i $result
#			echo $result >> $tmpfile
#			if [ $? -ne 0 ]; then
#				echo "Fail to read" $i
#				exit
#			fi
#		done
#}
#dump_location
#echo "Success"

result=$(readelf -SW $bin | grep " .text" | python elf-section.py)
echo ".text:" $result
echo $result > $tmpfile
## use " .data " to avoid finding out ".rodata" and ".data.rel.ro"
result=$(readelf -SW $bin | grep " .data " | python elf-section.py)
echo ".data:" $result
echo $result >> $tmpfile
result=$(readelf -SW $bin | grep " .bss"  | python elf-section.py)
echo " .bss:" $result
echo $result >> $tmpfile

echo
echo "Verify: cat "$tmpfile
cat $tmpfile
