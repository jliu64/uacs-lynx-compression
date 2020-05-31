/*
 * File: utils.cpp
 * Purpose: Various utility routines
 */

#include <cstdio>
#include <cstdlib>
#include <vector>
#include <list>
#include <map>
#include <string>
#include <cassert>
#include <unordered_set>
#include <algorithm>
#include <utility>
#include <iostream>
#include "slice.h"
#include "sliceState.h"
#include <libgen.h>
#include <xed-interface.h>
#include <xed-iclass-enum.h>

using namespace std;
using std::vector;
using std::unordered_set;

extern "C" {
    #include "../shared/LynxReg.h"
    #include <Reader.h>
    #include <Taint.h>
    #include <cfg.h>
    #include <cfgAPI.h>
    #include <cfgState.h>
    #include <controlTransfer.h>
}


void printUsage(char *program) {
    printf("Usage: %s [OPTIONS] trace_file 0xSlicingAddress\n", program);
    printf("  OPTIONS:\n");
    printf("    -b : begin the trace at a given function\n");
    printf("    -e : end the trace at a given function\n");
    printf("    -f : trace only the given function\n");
    printf("    -t : trace only the given thread\n");
    printf("    -i : generate cfg only from the given sources\n");
    printf("    -s : make CFG with superblocks\n");
    printf("    -c : compress the block size in the dot file\n");
    printf("    -v : print slice validation info\n");
    printf("    -r : keep registers involved in taint calculations when loading from mem\n");
    printf("    -h : print usage\n");
}


void parseCommandLine(int argc, char *argv[], SlicedriverState *driver_state) {
    if (argc < 3) {
      printUsage(argv[0]);
      exit(1);
    }

    int i;
    for(i = 1; i < argc; i++) {
        if(argv[i][0] == '-' && strlen(argv[i]) == 2) {
            switch(argv[i][1]) {
                case 'b':
                    driver_state->beginFn = argv[++i];
                    break;
                case 'e':
                    driver_state->endFn = argv[++i];
                    break;
                case 'f':
                    driver_state->traceFn = argv[++i];
                    break;
                case 't':
                    driver_state->targetTid = strtoul(argv[++i], NULL, 10);
                    break;
                case 'h':
                    printUsage(argv[0]);
                    break;
                case 'i':
                    driver_state->includeSrcs.push_back(++i);
                    break;
                case 's':
                    driver_state->makeSuperblocks = true;
                    break;
                case 'c':
                    driver_state->compress = true;
                    break;
                case 'v':
                    printf("Validating output will be created\n");
                    driver_state->validate = true;
                    break;
                case 'r':
                    printf("Keeping registers in taint calculation when loading memory addresses\n");
                    driver_state->keepReg = 1;
                    break;
                default:
                    fprintf(stderr, "Warning: Unknown Command Line Argument %s\n", argv[i]);
                    break;
            }
        }
        else {
            if(argv[i][0] == '0'){
              driver_state->sliceAddr = strtol(argv[i], NULL, 0);
            } else {
              driver_state->trace = argv[i];
            }
        }
    }

    return;
}

/*
 * print_slice_instrs() -- print out the instructions in the backward dynamic slice
 */
void print_slice_instrs(SliceState *slice) {
  std::set<cfgInstruction *>::iterator iter;
  cfgInstruction *cfg_ins;
  ReaderEvent rd_event;
  ReaderIns instr;
  xed_decoded_inst_t xedIns;
  xed_machine_mode_enum_t mmode;
  xed_address_width_enum_t stack_addr_width;
  xed_error_enum_t xed_err;
  char mnemonic[256];
  
  // initialize the XED tables -- one time.
  xed_tables_init();
  mmode=XED_MACHINE_MODE_LONG_64;
  stack_addr_width = XED_ADDRESS_WIDTH_64b;

  for (iter = slice->saveableCFGInstructions.begin();
       iter != slice->saveableCFGInstructions.end();
       ++iter) {
    cfg_ins = *iter;
    rd_event = (*iter)->event;
    assert(rd_event.type != EXCEPTION_EVENT);
    instr = rd_event.ins;

    xed_decoded_inst_zero(&xedIns);
    xed_decoded_inst_set_mode(&xedIns, mmode, stack_addr_width);
    xed_err = xed_decode(&xedIns, instr.binary, instr.binSize);
    assert(xed_err == XED_ERROR_NONE);

    getInsMnemonic(&xedIns, mnemonic, 256);
    printf("[ph: %d] %s  %lx    %s\n",
	   cfg_ins->phaseID, cfg_ins->block->fun->name, instr.addr, mnemonic);
    
  }
}

