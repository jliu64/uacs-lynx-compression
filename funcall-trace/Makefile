DEST = fncall_tracer

TOOLDIR = ..
XEDPATH = ../../xed

INCLUDES = -I$(TOOLDIR)/reader \
	-I$(TOOLDIR)/shared \
	-I$(XEDPATH)/include/public/xed \
	-I$(XEDPATH)/obj 
LDFLAGS = -L$(TOOLDIR)/reader -L$(XEDPATH)/obj
LIBS = -ltrd -lxed 

CC = gcc
CFLAGS = -Wall -g -DDEBUG -O2

CFILES = main.c print.c process_trace.c utils.c
OFILES = $(CFILES:.c=.o)

%.o : %.c
	$(CC) $(INCLUDES) $(CFLAGS) -c $<

$(DEST) : $(OFILES)
	$(CC) $(CFLAGS) $(OFILES) -o $(DEST) $(LDFLAGS) $(LIBS)

.PHONY: clean
clean:
	/bin/rm -f *.o *.BAK *~ $(OFILES) $(DEST)

