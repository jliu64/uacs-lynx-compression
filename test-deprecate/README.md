This project is a set of tools to assist in the testing of changes to the tracing tool to ensure that the same output is produced regardless of changes made. In this project, you will find two scripts. 

The first 'testCompiler.sh' is to ensure that over 2 runs of the same code, the same output is received. This script is meant to break with dynamic programs that may use threading and error checking in different ways throughout the execution of their program. 

The second 'testSingleThread.sh' is a 4 way diff checker that utilizes the 1:1 checking of different executions of the same program to check that that execution path is preserved, as well as checking that the new version of the tool adheres to those same changes.

Usage: In setup.sh, set the variables NEW_DIR and OLD_DIR to the correct versions of your uacs-lynx tool. ie OLD_DIR would be the directory with the original stable tool and NEW_DIR would be the version you were testing. Then run source ./setup.sh. After that, run either ./testCompiler.sh or ./testSingleThread.sh.

OLD_DIR and NEW_DIR should be paths to directories with setup.sh scripts that each set the variables: PIN, TRACE2ASCII, and TRACER64.