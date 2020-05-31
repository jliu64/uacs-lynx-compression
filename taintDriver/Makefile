
XED_DIR=../../../xed-install-base-2016-02-02-lin-x86-64/

CC=gcc
CXX=g++ -std=c++11
CFLAGS=-g
INCLUDES=-I$(XED_DIR)/include -I../reader -I../shared -I../taint -I../cfg
LIBPATHS=-L$(XED_DIR)/lib -L../reader -L../taint -L../cfg
LIBS=-ltrd -lxed -ltaint -lcfg

cntIns : cntIns.cpp
	$(CXX) $(CFLAGS) $(INCLUDES) -o $@ $^ $(LIBPATHS) $(LIBS)

identifyReads : identifyReads.cpp
	$(CXX) $(CFLAGS) $(INCLUDES) -o $@ $^ $(LIBPATHS) $(LIBS)

extractCfg : extractCfg.cpp
	$(CXX) $(CFLAGS) $(INCLUDES) -o $@ $^ $(LIBPATHS) $(LIBS)

extract : extract.cpp
	$(CXX) $(CFLAGS) $(INCLUDES) -o $@ $^ $(LIBPATHS) $(LIBS)

testDriver : testDriver.cpp
	$(CXX) -fpermissive $(CFLAGS) $(INCLUDES) -o $@ $^ $(LIBPATHS) $(LIBS)

getInterp : getInterp.cpp
	$(CXX) $(CFLAGS) $(INCLUDES) -o $@ $^ $(LIBPATHS) $(LIBS)

identify : identify.cpp
	$(CXX) $(CFLAGS) $(INCLUDES) -o $@ $^ $(LIBPATHS) $(LIBS)

extractInterp : extractInterp.cpp
	$(CXX) $(CFLAGS) $(INCLUDES) -o $@ $^ $(LIBPATHS) $(LIBS)


pathDriver : pathDriver.cpp
	$(CXX) $(CFLAGS) $(INCLUDES) -o $@ $^ $(LIBPATHS) $(LIBS)

sliceDriver : sliceDriver.cpp
	$(CXX) $(CFLAGS) $(INCLUDES) -o $@ $^ $(LIBPATHS) $(LIBS)

constDriver : constDriver.c
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^ $(LIBPATHS) $(LIBS)

calcSlice : calcSlice.cpp
	$(CXX) $(CFLAGS) $(INCLUDES) -o $@ $^ $(LIBPATHS) $(LIBS)


taintDriver : taintDriver.c
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^ $(LIBPATHS) $(LIBS)

clean :
	rm -rf identify extractInterp
