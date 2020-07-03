/*
 * File: process_trace.h
 * Purpose: Information about code defined in process_trace.c
 */

#ifndef __PROCESS_TRACE_H__
#define __PROCESS_TRACE_H__

#include "allocator-info.h"
#include "main.h"

typedef enum {
  CALL,
  RET
} InstrType;

/*
 * struct call_info stores information about call and ret instructions at
 * call-sites and return-sites in the simulated call-stacks.
 */
typedef struct call_info {
  uint64_t ins_num;
  uint64_t callins_num;    /* ins no. for a call instruction (used for ret
                              instructions to indicate the matching call instr */
  int tid;                 /* thread id */
  uint64_t instr_addr;     /* the address of the call or ret instruction */
  uint64_t retsite_addr;   /* the address the call should return to */
  char *caller_fn;         /* function name for the call instruction */
  char *callee_fn;         /* function name of the callee */
  char *mnemonic;          /* text representation of the instruction */
  InstrType ins_type;      /* instruction type: 0 = CALL, 1 = RET */
  struct allocation_info *alloc_info;
  struct call_info *prev, *next;  /* doubly-linked list */
} CallInfo;


/*
 * struct allocation_info stores information about allocations.  These structs
 * are not deallocated as the CallInfo stack entries are.
 */
typedef struct allocation_info {
  uint64_t ins_num;    /* ins no. for the call instruction */
  char *alloc_fn;      /* the name of the allocation function */
  int size;            /* the size of the allocation request */
  uint64_t start_addr;  /* start address of allocated memory region */
  uint64_t end_addr;   /* end address of allocated memory region */
  struct allocation_info *next;
} AllocationInfo;

/*******************************************************************************
 *                                                                             *
 *                                 PROTOTYPES                                  *
 *                                                                             *
 *******************************************************************************/

void proc_trace(FnTracer_State *f_state);
AllocInfo *get_alloc_info(FnTracer_State *f_state, char *fname);
uint64_t fn_arg_val(int n, FnTracer_State *f_state, int tid);
uint64_t untag(uint64_t ptr);

#endif  /* __PROCESS_TRACE_H__ */
