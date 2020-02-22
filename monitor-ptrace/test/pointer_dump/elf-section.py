import sys

lines = sys.stdin.readlines()
if len(lines) == 0:
	print '0x0 0x0'
	sys.exit()

line1 = lines[0]
line2 = lines[1]
first = line1.split("]")[1].split()[2]  # avoid the case of "[ 9] .text ...."
second = line2.split()[0]
print '0x' + first, '0x' + second
