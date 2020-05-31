#!/usr/bin/python
import os.path
import subprocess
import sys
import os

if("LD_LIBRARY_PATH" not in os.environ):
    os.environ['LD_LIBRARY_PATH'] = ""

trace = "../../../../../../pin -t ../../tracer/obj-intel64/Tracer.so -srcreg -memread -- ./"
cfgCheck = "../cfgchecker/cfgchecker "

# Make the executables and the cfg library
os.system("make")

# Create traces for each executable
testFiles = [executable for executable in os.listdir('.') if (executable.endswith(".o") or executable == "writeJmp" or executable == "fact_threaded")]
for test in testFiles:
	# run the tracer on the executable
        if test == "fact_threaded":
        	cmd = trace + test + " 4"
        else:
		cmd = trace + test
	print cmd
        # run the cfg checker on the executable
        os.system(cmd)
	cmd = cfgCheck + "trace.out"
        print cmd
        # If cfgchecker returns a non-zero value
        if os.WEXITSTATUS(os.system(cmd)):
                print "Failed test when running cfgChecker on " + trace
                exit(1)
	else:
		print "PASSED " + test
		print
	cmd = "mv ../traceSimple/trace.out.dot ../traceSimple/"+test+"s.dot"
        os.system(cmd)
print "All tests passed"
exit(0)
