# This make file assumes that the environment variable XED_ROOT points to the
# root of the directory tree containing the xed disassembler

CFILES = trace2ascii.c print.c utils.c
OFILES = $(CFILES:.c=.o)

CC=gcc
INCLUDES=-I$(XED_ROOT)/include/public/xed \
         -I$(XED_ROOT)/obj \
         -I../zlib/include \
         -I../reader \
         -I../shared
CFLAGS = -O3 -g 

LIBPATHS=-L$(XED_ROOT)/obj -L../zlib/lib -L../reader
LIBS=-ltrd -lxed -lz

%.o : %.c
	$(CC) $(INCLUDES) $(CFLAGS) -c $<

trace2ascii : $(OFILES) 
	$(CC) $(CFLAGS) $(OFILES) -o $@ $(LIBPATHS) $(LIBS)

clean :
	rm -rf *~ *.o trace2ascii
