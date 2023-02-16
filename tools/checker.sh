#!/bin/bash
### We should print .text .data .bss [addr, size]
#echo "Use:     (sudo) ./checker.sh binary shared_lib1.so shared_lib2.so ..."

BASEDIR=$(dirname "$0")
ELF="python $BASEDIR/elf-section.py"
bin=$1
sudo rm -rf /tmp/dec.info

echo $BASEDIR
echo ${ELF}

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

## dump the sections first
result=$(readelf -SW $bin | grep " .text" | ${ELF})
echo ".text:" $result
echo $result > $tmpfile
## use " .data " to avoid finding out ".rodata" and ".data.rel.ro"
result=$(readelf -SW $bin | grep " .data " | ${ELF})
echo ".data:" $result
echo $result >> $tmpfile
result=$(readelf -SW $bin | grep " .bss"  | ${ELF})
echo " .bss:" $result
echo $result >> $tmpfile
result=$(readelf -SW $bin | grep " .plt "  | ${ELF})
echo " .plt:" $result
echo $result >> $tmpfile
result=$(readelf -SW $bin | grep " .got.plt"  | ${ELF})
echo " .got.plt:" $result
echo $result >> $tmpfile

## dump function symbol and name
nm $bin | grep " T " >> $tmpfile
nm $bin | grep " t " >> $tmpfile
#result=$(nm $bin | grep " T ")
#echo $result >> $tmpfile

echo
#echo "Verify: cat "$tmpfile
#cat $tmpfile

## Create other files for each .so
for ((i = 2; i <= $#; i++ )); do
     printf '%s\n' "Shared lib name: $i: ${!i}"
      
     tmpfilename=$(echo ${!i} | sed -r "s/.+\/(.+)\..+/\1/").info
     tmpfilepath=/tmp/$tmpfilename
     rm -rf $tmpfilepath

     tempfile -n $tmpfilepath || exit
     echo "File" $tmpfilepath "created"
     ## dump the sections first
     result=$(readelf -SW ${!i} | grep " .text" | ${ELF})
     echo ".text:" $result
     echo $result > $tmpfilepath
     result=$(readelf -SW ${!i} | grep " .data" | ${ELF})
     echo ".data:" $result
     echo $result >> $tmpfilepath
     result=$(readelf -SW ${!i} | grep " .bss" | ${ELF})
     echo ".bss:" $result
     echo $result >> $tmpfilepath
     result=$(readelf -SW ${!i} | grep " .plt" | ${ELF})
     echo ".plt:" $result
     echo $result >> $tmpfilepath
     result=$(readelf -SW ${!i} | grep " .got.plt" | ${ELF})
     echo ".gotplt:" $result
     echo $result >> $tmpfilepath
done

