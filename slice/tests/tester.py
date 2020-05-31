#!/usr/bin/python
import os.path
import subprocess
import sys
import os

testFiles = [executable for executable in os.listdir('.') if (executable.endswith(".out"))]
for test in testFiles:
  slicingAddr = open(test[:-3] + "in").readline().strip()
  os.system("../sliceDriver -v " + test + " " + slicingAddr + " > sliceResults")
  print("Testing " + test[:-4])
  os.system("grep -wf " + test[:-3] + "baseResults" + " sliceResults > whatWePickedUpInSlice")
  os.system("diff -w whatWePickedUpInSlice " + test[:-3] + "baseResults")
  os.system("rm -rf sliceResults whatWePickedUpInSlice")
