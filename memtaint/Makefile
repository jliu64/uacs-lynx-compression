DEST = memtaint

TOOLDIR = ..
XEDPATH = ../../xed

INCLUDES = -I$(TOOLDIR)/reader \
	-I$(TOOLDIR)/taint \
	-I$(TOOLDIR)/shared \
	-I$(XEDPATH)/include/public/xed \
	-I$(XEDPATH)/obj 
LDFLAGS = -L$(TOOLDIR)/reader -L$(TOOLDIR)/taint -L$(XEDPATH)/obj
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

