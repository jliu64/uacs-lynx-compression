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

char *printRegOp(ReaderState *readerState, const char *prefix, LynxReg reg, uint32_t tid) {
  char *outstr;  // the output string
  int n, strsz, offset;

  reg = LynxReg2FullLynxIA32EReg(reg);
  n = LynxRegSize(reg);
  /*
   * strsz: a generous upper bound on the size of the output string.
   * We (lazily) assume that the prefix and the register name together
   * don't take up more than 28 bytes, and count an additional 4 bytes
   * for the ';', '=', space, and terminating '\0'.
   */
  strsz = 28 + 4;    /* prefix, register-name, ':', '=', ' ', '\0' */
  strsz += 2 * n + 1;    /* 2*n + 1 : length of the value of the string */
  outstr = malloc(strsz);

  reg = LynxReg2FullLynxIA32EReg(reg);
  offset = snprintf(outstr, 32, "%s:%s=", prefix, LynxReg2Str(reg));

  const uint8_t *val = getRegisterVal(readerState, reg, tid);

  for (int i = n-1; i >= 0; i--) {
    offset += snprintf(outstr+offset, 2+1, "%02x", val[i]);  /* +1 for trailing '\0' */
  }

  snprintf(outstr+offset, 1+1, " ");  /* +1 for trailing '\0' */

  return outstr;
}

char *printMemOp(ReaderState *readerState, const char *prefix, ReaderOp *op, uint32_t tid) {
  char *outstr, *s1, *s2, *s3;
  int n, strsz, offset;

  n = op->mem.size;
  /*
   * strsz: an upper bound on the size of the output string.
   * We assume that the prefix and address together take up at most 40 bytes
   * (actually, the prefix is at most 4 characters and the address is
   * at most 16 characters), and count an additional 5 bytes for the
   * ';', '=', space, and terminating '\0'.
   */
  strsz = 40;    /* prefix, address, '[', ']', '=', ' ', '\0' */
  strsz += 2 * n + 1;    /* 2*n + 1 : length of the value of the string */

  if (op->mem.seg != LYNX_INVALID) {
    s1 = printRegOp(readerState, "R", op->mem.seg, tid);
    strsz += strlen(s1);
  }
  if (op->mem.base != LYNX_INVALID) {
    s2 = printRegOp(readerState, "R", op->mem.base, tid);
    strsz += strlen(s2);
  }
  if (op->mem.index != LYNX_INVALID) {
    s3 = printRegOp(readerState, "R", op->mem.index, tid);
    strsz += strlen(s3);
  }
  
  outstr = malloc(strsz);
  offset = 0;
  
  if (!op->mem.addrGen) {
    offset = snprintf(outstr,
		      40,
		      "%s[%llx]=",
		      prefix,
		      (unsigned long long) op->mem.addr);
    uint8_t *buf = malloc(sizeof(uint8_t) * op->mem.size);

    getMemoryVal(readerState, op->mem.addr, op->mem.size, buf);

    for(int i = op->mem.size - 1; i >= 0; i--) {
      offset += snprintf(outstr+offset, 2+1, "%02x", buf[i]);  /* +1 for trailing '\0' */
    }
    
    offset += snprintf(outstr+offset, 1+1, " ");  /* +1 for trailing '\0' */

    free(buf);
  }

  if (op->mem.seg != LYNX_INVALID) {
    offset += snprintf(outstr+offset, strlen(s1)+1, "%s", s1);
    free(s1);
  }
  if (op->mem.base != LYNX_INVALID) {
    offset += snprintf(outstr+offset, strlen(s2)+1, "%s", s2);
    free(s2);
  }
  if (op->mem.index != LYNX_INVALID) {
    offset += snprintf(outstr+offset, strlen(s3)+1, "%s", s3);
    free(s3);
  }

  return outstr;
}


int main(int argc, char *argv[]) {
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
  char first = 1;

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
    if (curEvent.type == EXCEPTION_EVENT) {
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
    else if (curEvent.type == INS_EVENT) {
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
	if(hasBin) {
	  if(hasData) {
	    ReaderOp *curOp = info.readWriteOps;
	    for(i = 0; i < info.readWriteOpCnt; i++) {
	      if(curOp->type == MEM_OP) {
		char *s = printMemOp(readerState, "MW", curOp, curEvent.ins.tid);
		printf("%s", s);
		free(s);
	      }
	      else if (curOp->type == REG_OP) {
		char *s = printRegOp(readerState, "W", curOp->reg, curEvent.ins.tid);
		printf("%s", s);
		free(s);
	      }
	      curOp = curOp->next;
	    }

	    curOp = info.dstOps;
	    for(i = 0; i < info.dstOpCnt; i++) {
	      if(curOp->type == MEM_OP) {
		char *s = printMemOp(readerState, "MW", curOp, curEvent.ins.tid);
		printf("%s", s);
		free(s);
	      }
	      else if (curOp->type == REG_OP) {
		char *s = printRegOp(readerState, "W", curOp->reg, curEvent.ins.tid);
		printf("%s", s);
		free(s);
	      }
	      curOp = curOp->next;
	    }
	  }
	}
	printf(";\n");
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
	fetchInsInfo(readerState, &curEvent.ins, &info);
	int i;
	for (i = 0; i < curEvent.ins.binSize; i++) {
	  printf(" %02x", curEvent.ins.binary[i]);
	}
	printf("; %s; ", info.mnemonic);
	if (hasData) {
	  ReaderOp *curOp = info.srcOps;
	  for (i = 0; i < info.srcOpCnt; i++) {
	    if (curOp->type == MEM_OP) {
	      char *s = printMemOp(readerState, "MR", curOp, curEvent.ins.tid);
	      printf("%s", s);
	      free(s);
	    }
	    else if (curOp->type == REG_OP) {
	      char *s = printRegOp(readerState, "R", curOp->reg, curEvent.ins.tid);
	      printf("%s", s);
	      free(s);
	    }
	    curOp = curOp->next;
	  }

	  curOp = info.readWriteOps;
	  for (i = 0; i < info.readWriteOpCnt; i++) {
	    if (curOp->type == MEM_OP) {
	      char *s = printMemOp(readerState, "MR", curOp, curEvent.ins.tid);
	      printf("%s", s);
	      free(s);
	    }
	    else if (curOp->type == REG_OP) {
	    char *s = printRegOp(readerState, "R", curOp->reg, curEvent.ins.tid);
	    printf("%s", s);
	    free(s);
	  }
	  curOp = curOp->next;
	}
      }
    }
    }
    else {
      printf("UNKNOWN EVENT TYPE\n");
    }
  }    /* while */

  freeInsInfo(&info);
  closeReader(readerState);;

  return 0;
}
