DEST = slicer

# This make file assumes that the environment variable XED_ROOT points to the
# root of the directory tree containing the xed disassembler

TOOLDIR = ../

CXX = g++

INCLUDES = -I$(TOOLDIR)/zlib/include \
	-I$(TOOLDIR)/reader \
	-I$(TOOLDIR)/shared \
	-I$(XED_ROOT)/include/public/xed \
	-I$(XED_ROOT)/obj -I$(TOOLDIR)/cfg \
	-I$(TOOLDIR)/taint
LDFLAGS = -L$(TOOLDIR)/zlib/lib -L$(TOOLDIR)/reader -L$(XED_ROOT)/obj -L$(TOOLDIR)/cfg -L$(TOOLDIR)/taint
LIBS = -Wl,--whole-archive -lz -Wl,--no-whole-archive -lcfg -ltrd -lxed -ltaint

CXXFLAGS = -std=c++11 -Wall -g -DDEBUG -O2

CXXFILES = slice.cpp driver.cpp utils.cpp
OFILES = $(CXXFILES:.cpp=.o)

%.o : %.cpp
	$(CXX) $(INCLUDES) $(CXXFLAGS) -c $<

$(DEST) : $(OFILES)
	$(CXX) $(INCLUDES) $(CXXFLAGS) $(OFILES) -o $(DEST) $(LDFLAGS) $(LIBS)

.PHONY: clean
clean:
	/bin/rm -f *.o *.BAK *~ $(OFILES) $(DEST)

