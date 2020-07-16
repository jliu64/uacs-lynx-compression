# Using the Taint Library: A Tutorial

This document provides a high-level introduction to using the taint library.  It is not intended to be a detailed and exhaustive exposition of the taint library API; for this, please see the README file and the source code.

## Accessing the taint library
Accessing the taint library requires the following:

1) indicate where the compiler can find the relevant include files;
2) indicate which libraries the compiler should link against; and
3) indicate to the dynamic linker where to search for dynamically linked libraries.

Let `TOOLDIR` be the path to the directory containing the `taint` directory (i.e., the parent of this directory) and `XEDPATH` be the path to the directory containing Intel's XED disassembler.

- **Include files:** The include path for various header files mentioned below is given by:

  ```
  INCLUDES = -I$(TOOLDIR)/reader \
	-I$(TOOLDIR)/shared \
	-I$(TOOLDIR)/taint \
	-I$(XEDPATH)/include/public/xed \
	-I$(XEDPATH)/obj
	```

- **Libraries:** The reader uses the XED disassembler as a dynamically linked library `libxed.so`, which should be in the file `$(XEDFILE)/obj/libxed.so`.  For performance reasons, the reader is by default compiled into a statically linked library `libtrd.a` (however, if desired it can be compiled into a dynamically linked library using the make file `Makefile-dynamic`).  To specify the libraries, use

  ```
  LDFLAGS = -L$(TOOLDIR)/reader -L$(TOOLDIR)/taint -L$(XEDPATH)/obj
  LIBS = -ltrd -ltaint -lxed
  ```

- **Dynamic loader search path:** Set the variable `LD_LIBRARY_PATH` as follows:
    - `LD_LIBRARY_PATH` should include the directory `XEDPATH/obj`;
    - if the reader is built as a dynamically linked library, i.e., as a `*.so` file, then `LD_LIBRARY_PATH` should also include the directory `TOOLDIR/reader` (the default build process for the reader builds it as a statically shared library, i.e., as a `*.a` file, and it is not necessary to have the path to the reader in `LD_LIBRARY_PATH`);
    - if the taint library is built as a dynamically linked library, i.e., as a `*.so` file, then `LD_LIBRARY_PATH` should also include the directory `TOOLDIR/taint` (the default build process for the taint library builds it as a statically shared library, i.e., as a `*.a` file, and it is not necessary to have the path to the taint library in `LD_LIBRARY_PATH`).

Given the above, a makefile for a client application that uses the taint library might look something like the following:

```
TOOLDIR = .....
XEDPATH = .....

INCLUDES = -I$(TOOLDIR)/reader \
	-I$(TOOLDIR)/taint \
	-I$(TOOLDIR)/shared \
	-I$(XEDPATH)/include/public/xed \
	-I$(XEDPATH)/obj 
LDFLAGS = -L$(TOOLDIR)/reader -L$(TOOLDIR)/taint -L$(XEDPATH)/obj
LIBS = -ltrd -ltaint -lxed 

CC = gcc
CFLAGS = -Wall -g -O2

CFILES = .....
OFILES = $(CFILES:.c=.o)

%.o : %.c
	$(CC) $(INCLUDES) $(CFLAGS) -c $<

$(TARGET) : $(OFILES)
	$(CC) $(CFLAGS) $(OFILES) -o $(TARGET) $(LDFLAGS) $(LIBS)

```

