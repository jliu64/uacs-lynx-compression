/*
 * File: trace2ascii.h
 */

#ifndef __TRACE2ASCII_H__
#define __TRACE2ASCII_H__

typedef enum {
	      READ,
	      WRITE
} RW_flag;

typedef struct {
  char *trace;
  char *beginFn;
  uint32_t beginId;
  char *endFn;
  uint32_t endId;
  char *traceFn;
  uint32_t traceId;
  int64_t targetTid;
  uint64_t target_addr;
  uint8_t hasSrcReg;
  uint8_t hasMemRead;
  uint8_t hasData;
  uint8_t hasSrcId;
  uint8_t hasFnId;
  uint8_t hasAddr;
  uint8_t hasBin;
  uint8_t hasTid;
  uint8_t foundBeginFn;
  uint8_t foundTraceFn;
  uint8_t run;
  uint8_t addrSize;
  uint64_t endStackPtr;
  uint32_t endStackTid;
} Trace2Ascii_state;  

void parseCommandLine(int argc, char *argv[], Trace2Ascii_state *tstate);
int begin_trace_dump(ReaderEvent *curEvent,
		    ReaderState *readerState,
		     Trace2Ascii_state *tstate);
int end_trace_dump(Trace2Ascii_state tstate,
		   ReaderState *readerState,
		   ReaderEvent curEvent);
void printUsage(char *program);
void print_operand_info_after(ReaderState *readerState,
			      InsInfo *info,
			      ReaderEvent *curEvent);
int print_ins_info(Trace2Ascii_state tstate, uint64_t addr, uint64_t pos);
int print_ins(Trace2Ascii_state tstate,
	       ReaderEvent curEvent,
	       ReaderState *readerState,
	       InsInfo info,
	      uint64_t pos);

#endif  /* __TRACE2ASCII_H__ */
