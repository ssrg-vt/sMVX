### We should print .text .data .bss [addr, size]
#echo "Use:     (sudo) ./checker.sh binary "
echo "creating binary.info ..."
readelf -S $1 | grep " .text" -A 1 | python elf-section.py > binary.info
readelf -S $1 | grep " .data " -A 1 | python elf-section.py >> binary.info
readelf -S $1 | grep ".bss" -A 1 | python elf-section.py >> binary.info
readelf -S $1 | grep ".rel.dyn" -A 1 | python elf-section.py >> binary.info
readelf -S $1 | grep ".data.rel.ro " -A 1 | python elf-section.py >> binary.info
readelf -S $1 | grep ".rodata" -A 1 | python elf-section.py >> binary.info
