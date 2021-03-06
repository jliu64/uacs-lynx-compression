TARGETS = zlib reader trace2ascii cfg taint slice tracer

.PHONY: all clean

# This make file assumes that the environment variable XED_ROOT points to the
# root of the directory tree containing the xed disassembler

all : $(TARGETS)
ifndef XED_ROOT
	$(info "variable XED_ROOT undefined")
	$(info "please set XED_ROOT to point to the root of the xed disassembler")
	$(info "aborting...")
else
	chdir zlib; sh ./configure --prefix=`pwd` --static; make test; make install 
	make -C reader 
	make -C trace2ascii 
	make -C taint 
	make -C cfg 
	make -C slice
	chdir tracer; ./build.sh
endif

clean : $(TARGETS)
	cd zlib; make clean
	cd reader; make realclean
	cd trace2ascii ; make clean
	cd cfg ; make realclean
	cd taint ; make clean
	cd slice ; make clean
	cd tracer; make clean
