/*
 * File: process_trace.h
 * Purpose: Information about code defined in process_trace.c
 */

#ifndef __PROCESS_TRACE_H__
#define __PROCESS_TRACE_H__

#include "main.h"

typedef enum {
  CALL,
  RET
} InstrType;

typedef struct call_info {
  uint64_t ins_num;
  uint64_t callins_num;    /* ins no. for a call instruction (used for ret
                              instructions to indicate the matching call instr */
  uint64_t instr_addr;     /* the address of the call or ret instruction */
  uint64_t retsite_addr;   /* the address the call should return to */
  char *caller_fn;         /* function name for the call instruction */
  char *callee_fn;         /* function name of the callee */
#if 0
  uint8_t ins_sz;          /* size of the call instruction (bytes) */
  uint8_t ins_bytes[15];   /* the bytes of the call instruction */
#endif
  InstrType ins_type;      /* instruction type: 0 = CALL, 1 = RET */
  char *mnemonic;          /* text representation of the instruction */

  struct call_info *prev, *next;  /* doubly-linked list */
  
} CallInfo;

/*******************************************************************************
 *                                                                             *
 *                                 PROTOTYPES                                  *
 *                                                                             *
 *******************************************************************************/

void proc_trace(FnTracer_State *f_state);

#endif  /* __PROCESS_TRACE_H__ */
