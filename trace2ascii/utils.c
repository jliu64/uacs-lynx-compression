/*
 * File: utils.c
 * Purpose: Assorted utility code
 */

#include <Reader.h>
#include "stdio.h"
#include "trace2ascii.h"

void parseCommandLine(int argc, char *argv[], Trace2Ascii_state *tstate) {
  int i;
  char *endptr;
  /*
   * initialize state
   */
  tstate->trace = NULL;
  tstate->beginFn  = NULL;
  tstate->beginId = -1;
  tstate->endFn = NULL;
  tstate->endId = -1;
  tstate->traceFn = NULL;
  tstate->traceId = -1;
  tstate->targetTid = -1;
  tstate->target_addr = 0;
  /*
   * process command line
   */
  for (i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-a") == 0) {
      i++;
      tstate->target_addr = strtoull(argv[i], &endptr, 16);
      if (*endptr != '\0') {
	fprintf(stderr,
		"WARNING: target address %s contains unexpected characters: %s\n",
		argv[i],
		endptr);
      }
    }
    else if (strcmp(argv[i], "-b") == 0) {
      tstate->beginFn = argv[++i];
    }
    else if (strcmp(argv[i], "-e") == 0) {
      tstate->endFn = argv[++i];
    }
    else if (strcmp(argv[i], "-f") == 0) {
      tstate->traceFn = argv[++i];
    }
    else if (strcmp(argv[i], "-t") == 0) {
      tstate->targetTid = strtoul(argv[++i], NULL, 10);
    }
    else if (strcmp(argv[i], "-h") == 0) {
      printUsage(argv[0]);
      exit(0);
    }
    else if (argv[i][0] == '-') {
      fprintf(stderr, "Unknown option [ignoring]: %s\n", argv[i]);
    }
    else {
      tstate->trace = argv[i];
      break;
    }
  }
  
  return;
}

/*******************************************************************************
 *                                                                             *
 * begin_trace_dump() -- returns 1 if printing of the trace should begin,      *
 * 0 otherwise.                                                                *
 *                                                                             *
 *******************************************************************************/

int begin_trace_dump(ReaderEvent *curEvent,
		    ReaderState *readerState,
		    Trace2Ascii_state *tstate) {
  if (tstate->targetTid != -1 && curEvent->ins.tid != tstate->targetTid) {
    return 0;
  }

  if (!tstate->run) {
    if (!tstate->foundBeginFn) {
      if (curEvent->ins.fnId == tstate->beginId) {
	tstate->foundBeginFn = 1;
	tstate->run = (tstate->foundBeginFn && tstate->foundTraceFn);
      }
    }
    if (!tstate->foundTraceFn) {
      if (curEvent->ins.fnId == tstate->traceId) {
	tstate->foundTraceFn = 1;
	tstate->endStackTid = curEvent->ins.tid;
	tstate->endStackPtr = *((uint64_t *) getRegisterVal(readerState,
							    LYNX_RSP,
							    tstate->endStackTid));
	tstate->run = (tstate->foundBeginFn && tstate->foundTraceFn);
      }
    }

    if (!tstate->run) {
      return 0;
    }
  }

  return 1;
}


/*******************************************************************************
 *                                                                             *
 * end_trace_dump() -- returns 1 if printing of the trace should end, 0 o/w.   *
 *                                                                             *
 *******************************************************************************/

int end_trace_dump(Trace2Ascii_state tstate,
		   ReaderState *readerState,
		   ReaderEvent curEvent) {
  uint64_t stackPtr;
  
  if (tstate.endStackTid == curEvent.ins.tid) {
    stackPtr = *((uint64_t *) getRegisterVal(readerState,
					     LYNX_RSP,
					     tstate.endStackTid));
    if (stackPtr > tstate.endStackPtr) {
      return 1;
    }
  }
  
  if (curEvent.ins.fnId == tstate.endId) {
    return 1;
  }

  return 0;
}


