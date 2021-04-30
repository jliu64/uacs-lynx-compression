/*
 * File: print.c
 * Purpose: Assorted print routines for trace2ascii
 */

#include <stdio.h>
#include <Reader.h>
#include "trace2ascii.h"

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


void printRegOp(ReaderState *readerState, const char *prefix, LynxReg reg, uint32_t tid) {
    int i;

    reg = LynxReg2FullLynxIA32EReg(reg);
    printf("%s:%s=", prefix, LynxReg2Str(reg));

    const uint8_t *val = getRegisterVal(readerState, reg, tid);

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


/********************************************************************************
 *                                                                              *
 * print_operands() -- given a pointer to a sequence of operands along with a   *
 * count of operands to print, prints out the sequence of operands.             *
 *                                                                              *
 ********************************************************************************/

void print_operands(ReaderOp *first_op,
		    int op_count,
		    RW_flag rw,    /* 0: READ; if 1: WRITE */
		    ReaderState *readerState,
		    int tid) {
  int i;
  ReaderOp *cur_op;
  char* prefix;
  
  for (i = 0, cur_op = first_op; i < op_count; i++) {
    if (cur_op->type == MEM_OP) {
      prefix = (rw == READ ? "MR" : "MW");
      printMemOp(readerState, prefix, cur_op, tid);
    }
    else if (cur_op->type == REG_OP) {
      prefix = (rw == READ ? "R" : "W");
      printRegOp(readerState, prefix, cur_op->reg, tid);
    }

    cur_op = cur_op->next;
  }
}


/********************************************************************************
 *                                                                              *
 * print_operands_after() -- prints the values of an instruction's operands     *
 * after that instruction's execution.                                          *
 *                                                                              *
 ********************************************************************************/

/*
 * For technical reasons, it is convenient to record  src and dest operand values
 * for each instruction before that instruction is executed; this is what the
 * tracer does.  As a result, when the reader reads an instruction in an execution
 * trace, the register and memory values correspond to the program state *before* 
 * that instruction executes.  But people find it easier to understand a program's
 * behavior by associating each instruction with register and memory values *after*
 * that instruction has executed; this is what trace2ascii prints out.  To make 
 * this work, trace2ascii proceeds as follows: after reading an event (which gives
 * the program state before the current instruction, i.e., after the previous 
 * instruction) it first computes and prints out the operand values for the previous
 * instruction (i.e., after the previous instruction executed), then prints a 
 * newline, then prints out non-operand-value information about the current 
 * instruction.  The variable info holds information about the operands of an 
 * instruction, and this variable is not updated until after the operand values for
 * the previous instruction are printed out.
 */
void print_operand_info_after(ReaderState *readerState,
			      InsInfo *info,
			      ReaderEvent *curEvent) {
  ReaderOp *curOp;
  int i;

  print_operands(info->readWriteOps,
		 info->readWriteOpCnt,
		 WRITE,
		 readerState,
		 curEvent->ins.tid);

  print_operands(info->dstOps,
		 info->dstOpCnt,
		 WRITE,
		 readerState,
		 curEvent->ins.tid);

  printf(";\n");
}


/*******************************************************************************
 *                                                                             *
 * print_ins_info() -- returns 1 if information about the instruction at       *
 * address addr should be printed, 0 o/w.                                      *
 *                                                                             *
 *******************************************************************************/

int print_ins_info(Trace2Ascii_state tstate, uint64_t addr, uint64_t pos) {
  if (tstate.target_addr == 0) {
    return 1;
  }

  if (tstate.hasBin && tstate.hasData && tstate.hasAddr && tstate.target_addr == addr) {
    return 1;
  }

  return 0;
}


/*******************************************************************************
 *                                                                             *
 * print_ins() -- print information about n instruction                        *
 *                                                                             *
 *******************************************************************************/

int print_ins(Trace2Ascii_state tstate,
	       ReaderEvent curEvent,
	       ReaderState *readerState,
	       InsInfo info,
	       uint64_t pos) {
  printf("%ld:", pos);

  if (tstate.hasTid) {
    printf(" %d;", curEvent.ins.tid);
  }

  if (tstate.hasAddr) {
    printf(" 0x%llx;", (unsigned long long) curEvent.ins.addr);
  }

  if (tstate.hasSrcId) {
    printf(" %s;", fetchStrFromId(readerState, curEvent.ins.srcId));
  }

  if (tstate.hasFnId) {
    printf(" %s;", fetchStrFromId(readerState, curEvent.ins.fnId));
  }

  if (tstate.hasBin) {
    int i;
    for (i = 0; i < curEvent.ins.binSize; i++) {
      printf(" %02x", curEvent.ins.binary[i]);
    }
	
    printf("; %s; ", info.mnemonic);

    if (tstate.hasData) {
      print_operands(info.srcOps,
		     info.srcOpCnt,
		     READ,
		     readerState,
		     curEvent.ins.tid);

      print_operands(info.readWriteOps,
		     info.readWriteOpCnt,
		     READ,
		     readerState,
		     curEvent.ins.tid);
    }
  }

  return 1;
}


