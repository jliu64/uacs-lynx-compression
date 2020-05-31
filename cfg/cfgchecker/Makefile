TOOLDIR = ../..
XEDDIR = ../../../../xed-install-base-2016-02-02-lin-x86-64/

CC = gcc

IFLAGS = -I$(TOOLDIR)/reader -I$(TOOLDIR)/shared -I$(XEDDIR)include -I$(TOOLDIR)/cfg
LFLAGS = -L$(TOOLDIR)/reader -L$(XEDDIR)/lib -I$(TOOLDIR)/cfg

OFILES = $(CFILES:.c=.o)

cfgchecker : cfgchecker.c
	$(CC) -I. $(IFLAGS)  -g -Wall -o $@ $^ $(LFLAGS) -L.. $(LFLAGS) -lcfg -ltrd -lxed

.PHONY: clean
clean:
	/bin/rm -f *.o cfgchecker
