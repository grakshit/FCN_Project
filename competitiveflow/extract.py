# Given the standard output of our implementation, we split the output file
# into constituent flows. And process them accordingly.

import sys

if(len(sys.argv)<2):
	print('Usage: python extract.py trace_file')
	exit()

fname = sys.argv[1]

print fname

f = open(fname,'r')

out = dict()

for line in f:
	arr = line.strip().split(',')
	flow = arr[0]
        if "timeout" in line:
            continue
	try:
		out[flow].append(line)
	except KeyError:
		out[flow] = [line]

for i in range(len(out)):
        flow = out.keys()[i]
	f = open('flow'+str(i)+'.csv','w')
	for line in out[flow]:
		f.write(line)
	f.close()

