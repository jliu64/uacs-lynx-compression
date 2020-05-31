CC = gcc
CFLAGS = -Wall -g -DDEBUG 

% : %.c
	$(CC) $(CFLAGS) -o $@.o $< 

CFILES=$(wildcard *.c)
FILES=$(CFILES:.c=)

all: $(FILES)

.PHONY: clean
clean:
	/bin/rm -f *.o *.out
