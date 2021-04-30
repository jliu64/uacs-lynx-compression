/**
 * This is the driver for the trace2ascii tool. Most of the work is done by the 
 * trace reader (which is linked in as a library). This code just gets instructions
 * one by one and prints out the information to stdout. 
 **/

#include <Reader.h>
#include "stdio.h"
#include "trace2ascii.h"

/*******************************************************************************
 *                                                                             *
 * init_trace2ascii_state() -- initialize program state.                       *
 *                                                                             *
 *******************************************************************************/

ReaderState *init_trace2ascii_state(int argc, char *argv[], Trace2Ascii_state *tstate) {
  if (argc < 2) {
    printUsage(argv[0]);
    exit(1);
  }

  parseCommandLine(argc, argv, tstate);
  ReaderState *readerState = initReader(tstate->trace, 0);

  tstate->hasSrcReg = hasFields(readerState, getSelMask(SEL_SRCREG));
  tstate->hasMemRead = hasFields(readerState, getSelMask(SEL_MEMREAD));
  tstate->hasData = (hasFields(readerState, getSelMask(SEL_DESTREG))
		     || hasFields(readerState, getSelMask(SEL_MEMWRITE))
		     || tstate->hasSrcReg
	 	     || tstate->hasMemRead);
  tstate->hasSrcId = hasFields(readerState, getSelMask(SEL_SRCID));
  tstate->hasFnId = hasFields(readerState, getSelMask(SEL_FNID));
  tstate->hasAddr = hasFields(readerState, getSelMask(SEL_ADDR));
  tstate->hasBin = hasFields(readerState, getSelMask(SEL_BIN));
  tstate->hasTid = hasFields(readerState, getSelMask(SEL_TID));

  if (tstate->beginFn) {
    tstate->beginId = findString(readerState, tstate->beginFn);
    if (tstate->beginId == -1) {
      tstate->beginFn = NULL;
    }
  }

  if (tstate->endFn) {
    tstate->endId = findString(readerState, tstate->endFn);
    if(tstate->endId == -1) {
      tstate->endFn = NULL;
    }
  }

  if (tstate->traceFn) {
    tstate->traceId = findString(readerState, tstate->traceFn);
    if (tstate->traceId == -1) {
      tstate->traceFn = NULL;
    }
  }

  tstate->foundBeginFn = (tstate->beginFn == NULL);
  tstate->foundTraceFn = (tstate->traceFn == NULL);
  tstate->run = tstate->foundBeginFn && tstate->foundTraceFn;
  tstate->addrSize = getAddrSize(readerState);
  tstate->endStackPtr = 0;
  tstate->endStackTid = -1;

  return readerState;
}


/*******************************************************************************
 *                                                                             *
 * main()                                                                      *
 *                                                                             *
 *******************************************************************************/

int main(int argc, char *argv[]) {
  Trace2Ascii_state tstate;
  uint64_t prev_addr = 0, curr_addr = 0;
  ReaderEvent curEvent;
  InsInfo info;
  uint64_t n = 0;    /* current position in the trace */
  ReaderState *readerState = init_trace2ascii_state(argc, argv, &tstate);

  initInsInfo(&info);

  while (nextEvent(readerState, &curEvent)) {
    if (curEvent.type == INS_EVENT) {
      if (!begin_trace_dump(&curEvent, readerState, &tstate)) {
	continue;
      }
      if (end_trace_dump(tstate, readerState, curEvent)) {
	break;
      }
      /*
       * print out any operands written by the previous instruction
       */
      if (n > 0 && print_ins_info(tstate, prev_addr, n)) {
	print_operand_info_after(readerState, &info, &curEvent);
      }

      if (tstate.hasBin) {   /* Update info about the instruction's operands */
	fetchInsInfo(readerState, &curEvent.ins, &info);
      }
      prev_addr = curr_addr;
      curr_addr = curEvent.ins.addr;
      /*
       * print out info about the instruction if appropriate
       */
      if (print_ins_info(tstate, curEvent.ins.addr, n)) {
	print_ins(tstate, curEvent, readerState, info, n);
      }

      n += 1;
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
