import sys
from typing import Protocol

fname = sys.argv[1]
print("Processing file " + fname)

outname = sys.argv[2]
print("Writing file " + outname)

f = open(fname, 'r')
lines = f.readlines()
f.close

rules = []

for l in lines:
  words = l.strip().split()
  proto = ""
  print("Working with line ", words)
  if len(words) == 0 or words[0] != 'permit':
    continue
  else: 
    proto = words[1]
  if words[2] == 'any':
    words.pop(2)
  net = words[2]
  # "net 3.7.35.0/25 and tcp and port 443"
  rule = '(net ' + net + ' and ' + proto + ' and '
  if words[3] == 'eq':
    rule += '(port ' + words[4]
    for port in words[5:]:
      if port == 'any':
        break
      else:
        rule += ' or ' + port
    rule += '))'
  elif words[3] == 'range':
    rule += 'portrange ' + words[4] + '-' + words[5] + ')'
  rules.append(rule)

f = open(outname, "w")
composed = rules[0]
for rule in rules[1:]:
  composed += ' or ' + rule
f.write(composed)
f.close()