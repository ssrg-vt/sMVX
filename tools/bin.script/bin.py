#! /usr/bin/env python2
import lief
import sys

if len(sys.argv) != 2:
    print "Usage: ./bin.py [binary]"
    exit(0)

# ELF
binary = lief.parse(sys.argv[1])
for section in binary.sections:
    print section.name, section.size, len(section.content)

#text = binary.get_section(".text")
#text.content = "0x21"
#binary.write("ddd")
#print(binary)
