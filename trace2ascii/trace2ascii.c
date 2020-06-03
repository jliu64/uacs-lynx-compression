/**
 * This is the driver for the trace2ascii tool. Most of the work is done by the 
 * trace reader (which is linked in as a library). This code just gets instructions
 * one by one and prints out the information to stdout. 
 **/

#include <Reader.h>
#include "stdio.h"

char *trace = NULL;
char *beginFn  = NULL;
uint32_t beginId = -1;
char *endFn = NULL;
uint32_t endId = -1;
char *traceFn = NULL;
uint32_t traceId = -1;
int64_t targetTid = -1;
uint64_t target_addr = 0;

void printUsage(char *program) {
    printf("Usage: %s [OPTIONS] <trace>\n", program);
    printf("Options:\n");
    printf("  -a addr  : print only the instruction at address addr\n");
    printf("  -b fname : begin the trace at the function fname\n");
    printf("  -e fname : end the trace at the function fname\n");
    printf("  -f fname : trace only the function fname\n");
    printf("  -t t_id  : trace only the thread t_id\n");
    printf("  -h : print usage\n");
}

void parseCommandLine(int argc, char *argv[]) {
  int i;
  char *endptr;
  
  for (i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-a") == 0) {
      i++;
      target_addr = strtoull(argv[i], &endptr, 16);
      if (*endptr != '\0') {
	fprintf(stderr,
		"WARNING: target address %s contains unexpected characters: %s\n",
		argv[i],
		endptr);
      }
    }
    else if (strcmp(argv[i], "-b") == 0) {
      beginFn = argv[++i];
    }
    else if (strcmp(argv[i], "-e") == 0) {
      endFn = argv[++i];
    }
    else if (strcmp(argv[i], "-f") == 0) {
      traceFn = argv[++i];
    }
    else if (strcmp(argv[i], "-t") == 0) {
      targetTid = strtoul(argv[++i], NULL, 10);
    }
    else if (strcmp(argv[i], "-h") == 0) {
      printUsage(argv[0]);
      exit(0);
    }
    else if (argv[i][0] == '-') {
      fprintf(stderr, "Unknown option [ignoring]: %s\n", argv[i]);
    }
    else {
      trace = argv[i];
      break;
    }
  }
  
  return;
}

void printRegOp(ReaderState *readerState, const char *prefix, LynxReg reg, uint32_t tid) {
    reg = LynxReg2FullLynxIA32EReg(reg);
    printf("%s:%s=", prefix, LynxReg2Str(reg));

    const uint8_t *val = getRegisterVal(readerState, reg, tid);

    int i;
    for(i = LynxRegSize(reg) - 1; i >= 0; i--) {
        printf("%02x", val[i]);
    }

    printf(" ");
}

void printMemOp(ReaderState *readerState, const char *prefix, ReaderOp *op, uint32_t tid) {
    if(!op->mem.addrGen) {
        printf("%s[%llx]=", prefix, (unsigned long long) op->mem.addr);
        uint8_t *buf = malloc(sizeof(uint8_t) * op->mem.size);

        getMemoryVal(readerState, op->mem.addr, op->mem.size, buf);

        int i;
        for(i = op->mem.size - 1; i >= 0; i--) {
            printf("%02x", buf[i]);
        }
        printf(" ");

        free(buf);
    }

    if(op->mem.seg != LYNX_INVALID) {
        printRegOp(readerState, "R", op->mem.seg, tid);
    }
    if(op->mem.base != LYNX_INVALID) {
        printRegOp(readerState, "R", op->mem.base, tid);
    }
    if(op->mem.index != LYNX_INVALID) {
        printRegOp(readerState, "R", op->mem.index, tid);
    }
}

int main(int argc, char *argv[]) {
  uint64_t prev_addr = 0, curr_addr = 0;

  if (argc < 2) {
    printUsage(argv[0]);
    return 1;
  }

  parseCommandLine(argc, argv);

  ReaderState *readerState = initReader(trace, 0);

  ReaderEvent curEvent;

  uint8_t hasSrcReg = hasFields(readerState, getSelMask(SEL_SRCREG));
  uint8_t hasMemRead = hasFields(readerState, getSelMask(SEL_MEMREAD));
  uint8_t hasData = (hasFields(readerState, getSelMask(SEL_DESTREG))
		     || hasFields(readerState, getSelMask(SEL_MEMWRITE))
		     || hasSrcReg || hasMemRead);
  uint8_t hasSrcId = hasFields(readerState, getSelMask(SEL_SRCID));
  uint8_t hasFnId = hasFields(readerState, getSelMask(SEL_FNID));
  uint8_t hasAddr = hasFields(readerState, getSelMask(SEL_ADDR));
  uint8_t hasBin = hasFields(readerState, getSelMask(SEL_BIN));
  uint8_t hasTid = hasFields(readerState, getSelMask(SEL_TID));

  InsInfo info;
  initInsInfo(&info);
  char first = 1, ins_printed = 0;

  if (beginFn) {
    beginId = findString(readerState, beginFn);
    if (beginId == -1) {
      beginFn = NULL;
    }
  }

  if (endFn) {
    endId = findString(readerState, endFn);
    if(endId == -1) {
      endFn = NULL;
    }
  }

  if (traceFn) {
    traceId = findString(readerState, traceFn);
    if (traceId == -1) {
      traceFn = NULL;
    }
  }

  uint8_t foundBeginFn = (beginFn == NULL);
  uint8_t foundTraceFn = (traceFn == NULL);
  uint8_t run = foundBeginFn && foundTraceFn;
  uint8_t addrSize = getAddrSize(readerState);
  uint64_t endStackPtr = 0;
  uint32_t endStackTid = -1;

  uint64_t n = 0;
  while (nextEvent(readerState, &curEvent)) {
    if (curEvent.type == INS_EVENT) {
      if (targetTid != -1 && curEvent.ins.tid != targetTid) {
	continue;
      }

      if (!run) {
	if (!foundBeginFn) {
	  if (curEvent.ins.fnId == beginId) {
	    foundBeginFn = 1;
	    run = foundBeginFn && foundTraceFn;
	  }
	}
	if (!foundTraceFn) {
	  if (curEvent.ins.fnId == traceId) {
	    foundTraceFn = 1;
	    endStackTid = curEvent.ins.tid;
	    endStackPtr = *((uint64_t *) getRegisterVal(readerState, LYNX_RSP, endStackTid));
	    run = foundBeginFn && foundTraceFn;
	  }
	}

	if (!run) {
	  continue;
	}
      }

      if (first) {
	first = 0;
      }
      else {
	int i;
	if (target_addr == 0 || target_addr == prev_addr) {
	  if(hasBin && hasData) {
	  /*
	   * For technical reasons, it is convenient to record  src and dest operand
	   * values for each instruction before that instruction is executed; this is
	   * what the tracer does.  As a result, when the reader reads an instruction
	   * in an execution trace, the register and memory values correspond to the
	   * program state *before* that instruction executes.  But people find it 
	   * easier to understand a program's behavior by associating each instruction 
	   * with register and memory values *after* that instruction has executed;
	   * this is what trace2ascii prints out.  To make this work, trace2ascii
	   * proceeds as follows: after reading an event (which gives the program
	   * state before the current instruction, i.e., after the previous instruction)
	   * it first computes and prints out the operand values for the previous
	   * instruction (i.e., after the previous instruction executed), then prints
	   * a newline, then prints out non-operand-value information about the current
	   * instruction.  The variable info holds information about the operands of 
	   * an instruction, and this variable is not updated until after the operand
	   * values for the previous instruction are printed out.
	   */
	    ReaderOp *curOp = info.readWriteOps;
	    for(i = 0; i < info.readWriteOpCnt; i++) {
	      if(curOp->type == MEM_OP) {
		printMemOp(readerState, "MW", curOp, curEvent.ins.tid);
	      }
	      else if (curOp->type == REG_OP) {
		printRegOp(readerState, "W", curOp->reg, curEvent.ins.tid);
	      }
	      curOp = curOp->next;
	    }

	    curOp = info.dstOps;
	    for (i = 0; i < info.dstOpCnt; i++) {
	      if (curOp->type == MEM_OP) {
		printMemOp(readerState, "MW", curOp, curEvent.ins.tid);
	      }
	      else if (curOp->type == REG_OP) {
		printRegOp(readerState, "W", curOp->reg, curEvent.ins.tid);
	      }
	      curOp = curOp->next;
	    }
	  }
	}
      }

      if (ins_printed) {
	printf(";\n");
	ins_printed = 0;
      }

      if (endStackTid == curEvent.ins.tid) {
	uint64_t stackPtr = *((uint64_t *) getRegisterVal(readerState, LYNX_RSP, endStackTid));
	if(stackPtr > endStackPtr) {
	  break;
	}
      }
      if (curEvent.ins.fnId == endId) {
	break;
      }

      uint64_t this_instr = n++;

      if (target_addr != 0) {
	if (!(hasAddr && curEvent.ins.addr == target_addr)) {
	  continue;
	}
      }
	    
      printf("%ld:", this_instr);

      if (hasTid) {
	printf(" %d;", curEvent.ins.tid);
      }

      if (hasAddr) {
	printf(" 0x%llx;", (unsigned long long) curEvent.ins.addr);
      }

      if (hasSrcId) {
	printf(" %s;", fetchStrFromId(readerState, curEvent.ins.srcId));
      }

      if (hasFnId) {
	printf(" %s;", fetchStrFromId(readerState, curEvent.ins.fnId));
      }

      if (hasBin) {
	/*
	 * Update information about the source and destination operands of
	 * the instruction.
	 */
	fetchInsInfo(readerState, &curEvent.ins, &info);
	
	int i;
	for (i = 0; i < curEvent.ins.binSize; i++) {
	  printf(" %02x", curEvent.ins.binary[i]);
	}
	
	printf("; %s; ", info.mnemonic);
	prev_addr = curr_addr;
	curr_addr = curEvent.ins.addr;
	ins_printed = 1;

	if (hasData) {
	  ReaderOp *curOp = info.srcOps;
	  for (i = 0; i < info.srcOpCnt; i++) {
	    if (curOp->type == MEM_OP) {
	      printMemOp(readerState, "MR", curOp, curEvent.ins.tid);
	    }
	    else if (curOp->type == REG_OP) {
	      printRegOp(readerState, "R", curOp->reg, curEvent.ins.tid);
	    }
	    curOp = curOp->next;
	  }

	  curOp = info.readWriteOps;
	  for (i = 0; i < info.readWriteOpCnt; i++) {
	    if (curOp->type == MEM_OP) {
	      printMemOp(readerState, "MR", curOp, curEvent.ins.tid);
	    }
	    else if (curOp->type == REG_OP) {
	      printRegOp(readerState, "R", curOp->reg, curEvent.ins.tid);
	    }
	    curOp = curOp->next;
	  }
	}
      }
    }
    else if (curEvent.type == EXCEPTION_EVENT) {
      fflush(stdout);
      printf("EXCEPTION %d at %llx\n",
	     curEvent.exception.code,
	     (unsigned long long) curEvent.exception.addr);
      fflush(stdout);
      fprintf(stderr,
	      "EXCEPTION %d at %llx\n",
	      curEvent.exception.code,
	      (unsigned long long) curEvent.exception.addr);
    }

    else {
      printf("UNKNOWN EVENT TYPE\n");
    }
  }    /* while */

  freeInsInfo(&info);
  closeReader(readerState);;

  return 0;
}
