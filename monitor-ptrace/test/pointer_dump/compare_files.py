#! /usr/bin/python
import sys

print len(sys.argv)

if len(sys.argv) != 3:
    print "wrong params"
    sys.exit(1)

with open(sys.argv[1], 'r') as file1:
    with open(sys.argv[2], 'r') as file2:
        same = set(file1).intersection(file2)

same.discard('\n')

for line in same:
    print line
#with open('some_output_file.txt', 'w') as file_out:
#    for line in same:
#        file_out.write(line)
