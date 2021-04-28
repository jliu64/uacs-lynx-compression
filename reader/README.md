# Reader #

This directory contains code necessary to build the toolset's trace reader. The reader will be used to read a trace in from the binary format used by the tracer so that programs can analyze the trace. It's design allows the user to walk through a trace instruction by instruction and make queries to the shadow state maintained by the reader.

## Prerequesites ##

Linux

* [Intel's XED disassembler](https://software.intel.com/en-us/articles/xed-x86-encoder-decoder-software-library)

## Building ##

1. Checkout the code for Xed into the above directory and build it (Note, this is automatically done in the build.sh script in the above directory)
2. Run make

## Linking to the library ##

Since the reader a library, you'll have to write your own executable and compile against the library. To do so, you'll need to add -ltrd and -lxed to the link command. If the linker complains that it can't find those libraries, also add -L$THIS_DIR and -L$XED_BASE/lib to your link command.

## Documentation ##
* A tutorial on using the trace reader is available in the file [HOW-TO-USE.md](HOW-TO-USE.md).

* A brief summary of the API presented by the trace reader is available in the file [API.md](API.md).

## Common Errors ##

 When trying to run an executable that uses the reader, you may get the error

    ./<executable>: error while loading shared libraries: libtrd.so: cannot open shared object file: No such file or directory
    
To fix this problem, add the path to the missing library to the environment variable $LD_LIBRARY_PATH (the same error may occur with `libxed` as well)

