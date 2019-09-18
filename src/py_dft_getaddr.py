#!/usr/bin/env python2
import r2pipe
import sys

total_lines = 0
app_code_lines = 0

## args pre-processing
if len(sys.argv) != 3:
    print "Usage ./py_getaddr.py [binary] [dft log]"
    exit(0)

## process the logs
result = []
with open(sys.argv[2], "r") as infile:
    for line in infile:
        total_lines += 1
        if line[2] != '8':  # only want app code
            continue
        result.append(line.split(':')[0])

print "Finish processing large file ..."
print "Total lines of app code:", len(result)
app_code_lines = len(result)

final = list(dict.fromkeys(result))
final.sort()

print len(final), "addresses found in the taint trace!"
print final
print ""

## extract functions from the binary
functions = []
print "The function names + offsets are:"
r2 = r2pipe.open(sys.argv[1])
for addr in final:
    cmd_res = r2.cmd("fd " + addr)
    print addr, ":", cmd_res,
    functions.append(cmd_res.split()[0])
r2.quit()

function = list(dict.fromkeys(functions))

## print the final results
print "\n==== Results ===="
print app_code_lines,"/",total_lines, "of application instructions access taint memory (total include libc)"
print len(function),"/",len(functions), "functions after deduplicatation (total)"

print "\n=== Functions ==="
for f in function:
    print f
