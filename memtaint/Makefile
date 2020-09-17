DEST = memtaint

# This make file assumes that the environment variable XED_ROOT points to the
# root of the directory tree containing the xed disassembler

TOOLDIR = ..

INCLUDES = -I$(TOOLDIR)/reader \
	-I$(TOOLDIR)/taint \
	-I$(TOOLDIR)/shared \
	-I$(XED_ROOT)/include/public/xed \
	-I$(XED_ROOT)/obj 
LDFLAGS = -L$(TOOLDIR)/reader -L$(TOOLDIR)/taint -L$(XED_ROOT)/obj
LIBS = -ltrd -ltaint -lxed 

CC = gcc
CXX = g++
CFLAGS = -Wall -g -DDEBUG -O2

CFILES = main.c print.c process_trace.c utils.c
OFILES = $(CFILES:.c=.o)

%.o : %.c
	$(CC) $(INCLUDES) $(CFLAGS) -c $<

$(DEST) : $(OFILES)
	$(CXX) $(CFLAGS) $(OFILES) -o $(DEST) $(LDFLAGS) $(LIBS)

.PHONY: clean
clean:
	/bin/rm -f *.o *.BAK *~ $(OFILES) $(DEST)

