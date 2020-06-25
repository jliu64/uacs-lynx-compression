/*
 * File: process_trace.h
 * Purpose: Information about code defined in process_trace.c
 */

#ifndef __PROCESS_TRACE_H__
#define __PROCESS_TRACE_H__

#include "main.h"

typedef struct callsite_info {
  uint64_t ins_num;
  uint64_t callsite_addr;  /* the address of the call instruction */
  uint64_t retsite_addr;   /* the address the call should return to */
  char *caller_fn;         /* function name for the call instruction */
  char *callee_fn;         /* function name of the callee */
  uint8_t ins_sz;          /* size of the call instruction (bytes) */
  uint8_t ins_bytes[15];   /* the bytes of the call instruction */
  char *mnemonic;          /* text representation of the instruction */

  struct callsite_info *prev, *next;  /* doubly-linked list */
  
} CallsiteInfo;

/*******************************************************************************
 *                                                                             *
 *                                 PROTOTYPES                                  *
 *                                                                             *
 *******************************************************************************/

void proc_trace(FnTracer_State *f_state);

#endif  /* __PROCESS_TRACE_H__ */
