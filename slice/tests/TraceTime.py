#!/usr/bin/python
import os.path
import subprocess
import sys
import os

fi = open("tracetimeOutput", "a")
numTests = 5
os.system("echo \"Testing Time\" > ./tracetimeOutput")
for i in range(numTests):
  os.system("~/speedImprovementsStock/source/tools/ScienceUpToPar/Tools/inputDetection/inputDetectDriver dynamicallyModifiedTest.out 0x40a53000 >> tracetimeOutput")

fi = open("tracetimeOutput", "r")
lin = fi.readlines()
sumTrace = 0
for i in range(1, len(lin), 1):
  sumTrace+=int(lin[i])

print("Trace Average Construction Time: " + str(sumTrace/numTests))
