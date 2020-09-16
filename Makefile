#TARGETS = reader trace2ascii cfg cfg2dot strdump trace2callgraph taint slice 
TARGETS = reader trace2ascii cfg taint slice 

.PHONY: all clean

all : $(TARGETS)
	make -C reader 
	make -C trace2ascii 
	make -C taint 
	make -C cfg 
#	make -C cfg2dot 
#	make -C strdump 
#	make -C trace2callgraph 
	make -C slice 

clean : $(TARGETS)
	cd reader; make clean
	cd trace2ascii ; make clean
	cd cfg ; make clean
#	cd cfg2dot ; make clean
#	cd strdump ; make clean
#	cd trace2callgraph ; make clean
	cd taint ; make clean
	cd slice ; make clean


