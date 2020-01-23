import sys

lines = sys.stdin.readlines()
if len(lines) == 0:
	print '0x0 0x0'
	sys.exit()

line = lines[0]
second = line.split(']')[1]
print '0x' + second.split()[2], '0x' + second.split()[4]
