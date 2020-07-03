/*
 * File: process_trace.c
 * Purpose: Process an execution trace and print out function call/return info.
 * Author: Saumya Debray
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "allocator-info.h"
#include "main.h"
#include "print.h"
#include "utils.h"

/*
 * callstack_vec points to an array of stacks of CallInfo structs.  This array
 * is allocated in the function proc_trace() with size = max. no. of threads in
 * the trace being processed (obtained from the reader).  The elements of the
 * array are indexed by thread_id, with each element using a linked list to
 * simulate the call stack of the  corresponding thread.
 *
 * retinfo_vec is an array of CallInfo structs that holds per-thread information
 * about ret instructions.
 *
 * unproc_call and unproc_ret are arrays of flags, similarly indexed by thread-id,
 * which indicate whether there is a partially-processed call or ret instruction
 * for any given thread.
 */
static CallInfo **callstack_vec, *call_list = NULL;
static CallInfo **retinfo_vec, *ret_info;
static uint8_t *unproc_call, *unproc_ret;
static int n_threads;
static AllocationInfo *alloc_info = NULL;
/*
 * arg_regs: for argument passing registers in the standard calling convention
 */
LynxReg arg_regs[] = {
  LYNX_RDI,
  LYNX_RSI,
  LYNX_RDX,
  LYNX_RCX,
  LYNX_R8,
  LYNX_R9
};

/*******************************************************************************
 *                                                                             *
 *                                 PROTOTYPES                                  *
 *                                                                             *
 *******************************************************************************/

static void free_csite_info(uint64_t retsite_addr, int tid);
static CallInfo *find_call_info(uint64_t retsite_addr, int tid);
static uint64_t reg_val(FnTracer_State *f_state, LynxReg reg, int tid);
void chk_heap_write(FnTracer_State *f_state, uint64_t ins_num, int tid);

/*******************************************************************************
 *                                                                             *
 * print_callstack_vec() -- print out the vector of call stacks.  Debugging.   *
 *                                                                             *
 *******************************************************************************/
#ifdef DEBUG
static void print_callstack_vec(char *s) {
  int i;
  CallInfo *ctmp;

  printf("--------------- CALLSTACK_VEC [n_threads = %d] %s ---------------\n",
	 n_threads, s);
  for (i = 0; i < n_threads; i++) {
    printf("TID %d: ", i);
    for (ctmp = callstack_vec[i]; ctmp != NULL; ctmp = ctmp->prev) {
      printf("%ld [c: %lx; r: %lx]; ", ctmp->ins_num, ctmp->instr_addr, ctmp->retsite_addr);
    }
    printf("\n");
  }

  printf("**********************************************************************\n\n");
}
#endif


/*******************************************************************************
 *                                                                             *
 * init_call_info() -- initialize info for a call instruction.                 *
 *                                                                             *
 *******************************************************************************/

static void init_call_info(FnTracer_State *f_state,
			   ReaderIns *instr,
			   uint64_t n,
			   int tid) {
  CallInfo *csite = alloc(sizeof(CallInfo));
  csite->ins_type = CALL;
  csite->callins_num = csite->ins_num = n;  
    
  csite->tid = tid;
  
  if (f_state->has_addr) {
    csite->instr_addr = instr->addr;
    csite->retsite_addr = csite->instr_addr + instr->binSize;
  }
  
  if (f_state->has_fn_id) {
    csite->caller_fn = strdup(fetchStrFromId(f_state->reader_state, instr->fnId));
  }
  
  csite->callee_fn = NULL;

  if (f_state->has_bin) {
    csite->mnemonic = strdup(f_state->ins_info->mnemonic);
  }
  /*
   * push csite on the global stack of CallInfo structs for this thread-id
   */
  csite->prev = callstack_vec[tid];
  if (callstack_vec[tid] != NULL) {
    callstack_vec[tid]->next = csite;
  }
  callstack_vec[tid] = csite;
  unproc_call[tid] = 1;

#ifdef DEBUG
  print_callstack_vec("init_call_info");
#endif

}


/*******************************************************************************
 *                                                                             *
 * init_ret_info() -- initialize info for a ret instruction.                   *
 *                                                                             *
 *******************************************************************************/

static void init_ret_info(FnTracer_State *f_state,
			  ReaderIns *instr,
			  uint64_t n,
			  int tid) {

  ret_info = retinfo_vec[tid];
  ret_info->ins_num = n;
  ret_info->ins_type = RET;

  if (f_state->has_tid) {
    ret_info->tid = instr->tid;
  }
  
  if (f_state->has_addr) {
    ret_info->instr_addr = instr->addr;
    ret_info->retsite_addr = 0;
  }
  
  ret_info->caller_fn = NULL;
  if (f_state->has_fn_id) {
    ret_info->callee_fn = strdup(fetchStrFromId(f_state->reader_state, instr->fnId));
  }

  if (f_state->has_bin) {
    ret_info->mnemonic = strdup(f_state->ins_info->mnemonic);
  }
}


/*******************************************************************************
 *                                                                             *
 * update_callret_info() -- if the current instruction follows a call (in the  *
 * same thread), update the CallInfo struct for the callsite with callee and   *
 * argument values, then print the call if appropriate; if the current         *
 * instruction follows a ret (in the same thread), update the CallInfo struct  *
 * for the return site with the caller, then print the call if appropriate.    *
 *                                                                             *
 *******************************************************************************/

static void update_callret_info(FnTracer_State *f_state, ReaderIns *instr, int tid) {
  CallInfo *csite;
  AllocInfo *ainfo;
  AllocationInfo *allocation_info = NULL;
  uint64_t retval;

  /****************************** PROCESS A CALL ******************************/
  /*
   * The name of the callee function is obtained as the function that the
   * instruction following the call instruction belongs to.  To indicate that
   * the previous instruction was a call, the variable instr_was_call is set 
   * to 1.  In this case, the entry at the top of the CallInfo stack has
   * all the relevant fields except for the callee name filled in when the
   * call instruction (the instruction preceding this one) was processed.
   */
  if (unproc_call[tid] != 0) {
    call_list = callstack_vec[tid];
    call_list->callee_fn = strdup(fetchStrFromId(f_state->reader_state, instr->fnId));
    /*
     * if the called function is a known allocation function, record information
     * about the allocation request
     */
    if ((ainfo = get_alloc_info(f_state, call_list->callee_fn)) != NULL) {
      allocation_info = alloc(sizeof(AllocationInfo));
      allocation_info->ins_num = call_list->ins_num;
      allocation_info->alloc_fn = strdup(call_list->callee_fn);
      allocation_info->size = eval(ainfo->ast, f_state, tid);
      call_list->alloc_info = allocation_info;
      /*
       * add this allocation record to the global list of such records
       */
      allocation_info->next = alloc_info;
      alloc_info = allocation_info;
    }
  }
  unproc_call[tid] = 0;
  
  /****************************** PROCESS A RETURN *****************************/
  if (unproc_ret[tid] != 0) {
    ret_info = retinfo_vec[tid];
    ret_info->caller_fn = strdup(fetchStrFromId(f_state->reader_state, instr->fnId));
    csite = find_call_info(instr->addr, tid);
    if (csite != NULL) {
      ret_info->callins_num = csite->ins_num;
      allocation_info = csite->alloc_info;
    }
    /*
     * if allocation_info != NULL, this means that the called function is a known
     * allocation function.  In this case, record information about the result of
     * the allocation request, i.e., the start and end address of the allocated 
     * memory block.
     */
    if (allocation_info != NULL) {
      retval = reg_val(f_state, LYNX_RAX, tid);
      /*
       * V8 uses tagged pointers, where the low bit of a pointer is always set to 1
       * (see https://medium.com/@stankoja/v8-bug-hunting-part-2-memory-
       * representation-of-js-types-ea37571276b8).  We undo this by clearing the
       * low bit.
       */
      retval = untag(retval);
      
      allocation_info->start_addr = retval;
      allocation_info->end_addr = allocation_info->start_addr + allocation_info->size - 1;

      print_instr(ret_info, allocation_info);
    }

    free_csite_info(instr->addr, tid);
    unproc_ret[tid] = 0;
  }
}


/*******************************************************************************
 *                                                                             *
 * proc_instr() -- process a single instruction                                *
 *                                                                             *
 *******************************************************************************/

static void proc_instr(FnTracer_State *f_state, ReaderIns *instr, uint64_t n) {
  xed_iclass_enum_t instr_op;
  int tid;

  tid = instr->tid;
  update_callret_info(f_state, instr, tid);

  instr_op = f_state->ins_info->insClass;

  switch (instr_op) {
  case XED_ICLASS_CALL_FAR:
  case XED_ICLASS_CALL_NEAR:
    init_call_info(f_state, instr, n, tid);
    break;

  case XED_ICLASS_RET_FAR:
  case XED_ICLASS_RET_NEAR:
  case XED_ICLASS_IRET:
  case XED_ICLASS_IRETD:
  case XED_ICLASS_IRETQ:
    init_ret_info(f_state, instr, n, tid);
    unproc_ret[instr->tid] = 1;
    break;
    
  default:
    if (f_state->chk_heap) {
      chk_heap_write(f_state, n, tid);
    }

    break;
  }

}

/*******************************************************************************
 *                                                                             *
 * find_call_info() -- given a return address and a thread id, return a        *
 * pointer to the corresponding call the CallInfo stack, if one exists;        *
 * NULL otherwise.                                                             *
 *                                                                             *
 *******************************************************************************/
  
static CallInfo *find_call_info(uint64_t retsite_addr, int tid) {
  CallInfo *ctmp;
  for (ctmp = callstack_vec[tid]; ctmp != NULL; ctmp = ctmp->prev) {
    if (ctmp->retsite_addr == retsite_addr) {
      return ctmp;
    }
  }

#ifdef DEBUG
  print_callstack_vec("find_call_info");
#endif

  return NULL;
}

/*******************************************************************************
 *                                                                             *
 * get_alloc_info() -- given a function name, returns a pointer to its         *
 * AllocInfo structure if one is found, NULL otherwise.                        *
 *                                                                             *
 *******************************************************************************/

AllocInfo *get_alloc_info(FnTracer_State *f_state, char *fname) {
  AllocInfo *a_info;
  int i, n;

  n = f_state->n_allocfuns;
  for (i = 0; i < n; i++) {
    a_info = &(f_state->alloc_info[i]);
    if (strcmp(a_info->fname, fname) == 0) {
      return a_info;
    }
  }

  return NULL;
}


/*******************************************************************************
 *                                                                             *
 * proc_trace() -- read the trace and process its instructions                 *
 *                                                                             *
 *******************************************************************************/

void proc_trace(FnTracer_State *f_state) {
  uint64_t ins_num = 0;
  ReaderEvent curr_event;
  int i;

  /*
   * allocate storage for per-thread information on calls and returns.  The arrays
   * allocated here are zero-initialized by alloc().
   */
  n_threads = f_state->reader_state->exInfo.numThreads;
  callstack_vec = alloc(n_threads * sizeof(CallInfo *));

  retinfo_vec = alloc(n_threads * sizeof(CallInfo *));
  for (i = 0; i < n_threads; i++) {
    retinfo_vec[i] = alloc(sizeof(CallInfo));
  }

  unproc_call = alloc(n_threads);  /* flag indicating partially-processed call */
  unproc_ret = alloc(n_threads);   /* flag indicating partially-processed ret */
  /*
   * now process the trace
   */
  while (nextEvent(f_state->reader_state, &curr_event)) {
    if (curr_event.type == INS_EVENT) {
      fetchInsInfo(f_state->reader_state, &curr_event.ins, f_state->ins_info);

      ins_num += 1;
      proc_instr(f_state, &(curr_event.ins), ins_num);
    }
    else if (curr_event.type == EXCEPTION_EVENT) {
      msg(stderr,
	  "EXCEPTION %d at %llx\n",
	  curr_event.exception.code,
	  (unsigned long long) curr_event.exception.addr);
    }
    else {
      msg(stdout, "UNKNOWN EVENT TYPE\n");
    }
  }    /* while */
}

/*******************************************************************************
 *                                                                             *
 * free_csite_info() -- deallocate a CallInfo structure.                       *
 *                                                                             *
 *******************************************************************************/

static void free_csite_info(uint64_t retsite_addr, int tid) {
  CallInfo *ctmp, *ctmp_prev;
  uint64_t this_retsite_addr;
  /*
   * Check whether the return address appears on the CallInfo stack (it may not, 
   * e.g., in the case of a ROP sequence).
   */
  if (find_call_info(retsite_addr, tid) == NULL) {
    ret_info = retinfo_vec[tid];
    printf("WARNING [%ld]: return address 0x%lx [fun: %s] not found on call stack\n",
	   ret_info->ins_num, retsite_addr, ret_info->callee_fn);
    return;
  }
  /*
   * retsite_addr appears on the call stack.  Pop the call stack up to and
   * including the corresponding call site.
   */
  for (ctmp = callstack_vec[tid]; ctmp != NULL; ctmp = ctmp_prev) {
#ifdef DEBUG
    printf("+++ free_csite_info [tid = %d, retsite_addr = %lx]: popping: %ld [c: %lx, r: %lx]\n",
	   tid, retsite_addr, ctmp->ins_num, ctmp->instr_addr, ctmp->retsite_addr);
#endif
    ctmp_prev = ctmp->prev;
    this_retsite_addr = ctmp->retsite_addr;

    callstack_vec[tid] = callstack_vec[tid]->prev;
    if (callstack_vec[tid] != NULL) {
      callstack_vec[tid]->next = NULL;
    }
    
    if (ctmp->caller_fn != NULL) free(ctmp->caller_fn);
    if (ctmp->callee_fn != NULL) free(ctmp->callee_fn);
    if (ctmp->mnemonic != NULL) free(ctmp->mnemonic);
    free(ctmp);

    if (this_retsite_addr == retsite_addr) {
      break;
    }
  }

#ifdef DEBUG
  print_callstack_vec("AFTER free_csite_info");

#endif
}


/*******************************************************************************
 *                                                                             *
 * reg_val() -- return the value of the register specified for the thread and  *
 * reader_state given.                                                         *
 *                                                                             *
 *******************************************************************************/

static uint64_t reg_val(FnTracer_State *f_state, LynxReg reg, int tid) {
  char *value_string, *ptr;
  int i;

  reg = LynxReg2FullLynxIA32EReg(reg);

  value_string = alloc(2*LynxRegSize(reg) + 1);  /* + 1 for the trailing NUL */

  const uint8_t *val = getRegisterVal(f_state->reader_state, reg, tid);

  for(ptr = value_string, i = LynxRegSize(reg) - 1; i >= 0; i--, ptr += 2) {
    sprintf(ptr, "%02x", val[i]);
  }

  return strtoul(value_string, NULL, 16);
}


/*******************************************************************************
 *                                                                             *
 * fn_arg_val() -- given an argument number and execution state, returns the   *
 * value of that argument.  The first argument is arg# 0.                      *
 *                                                                             *
 * The standard calling convention for Linux binaries passes the first six     *
 * arguments in registers and any remaining arguments on the stack.  For now   *
 * we only handle values in registers.  It should be easy to extend this to    *
 * also grab arguments passed on the stack; this is TBD.                       *
 *                                                                             *
 *******************************************************************************/

uint64_t fn_arg_val(int n, FnTracer_State *f_state, int tid) {
  if (n > 6) {
    msg(stderr, "FIXME: function arguments > 6 not currently handled\n");
    return 0;
  }

  return reg_val(f_state, arg_regs[n], tid);
}


/*******************************************************************************
 *                                                                             *
 * untag() -- transform tagged pointers to untagged ones (system-dependent).   *
 *                                                                             *
 *******************************************************************************/

uint64_t untag(uint64_t ptr) {
#ifdef SYSTEM_IS_V8
  return (ptr & ~(0x1UL));
#endif    /* SYSTEM_IS_V8 */

  return ptr;    /* default: do nothing */
}


/*******************************************************************************
 *                                                                             *
 * op_chk_OOB_heap_access() -- check whether the address accessed by a memory  *
 * operand seems to be an out-of-bounds heap access.  If so, return 1;         *
 * otherwise return 0.                                                         *
 *                                                                             *
 *******************************************************************************/

int op_chk_OOB_heap_access(ReaderOp *op,
			   FnTracer_State *f_state,
			   uint64_t ins_num,
			   int tid) {
  InsInfo *info = f_state->ins_info;
  AllocationInfo *ainfo;
  LynxReg base_reg;
  uint64_t base_addr, addr;

  addr = op->mem.addr;  /* address accessed by this operand */
      
  base_reg = op->mem.base;
  if (base_reg == LYNX_RSP) {
    return 0;    /* ignore writes to the stack */
  }

  base_addr = untag(reg_val(f_state, base_reg, tid));  /* address in base reg */
  /*
   * Search through the list of allocation information to see whether
   * there is any region for which this could be an OOB access.
   */
  for (ainfo = alloc_info; ainfo != NULL; ainfo = ainfo->next) {
    if (base_addr == ainfo->start_addr && addr > ainfo->end_addr) {
      return 1;  /* OOB */
    }

#if 1
    /*
     * if the address accessed falls within an allocated region but the base
     * register does not match the start address of the region, flag this so
     * we can try to figure out what we should do.
     */      
    if (addr >= ainfo->start_addr
	&& addr <= ainfo->end_addr
	&& base_addr != ainfo->start_addr) {
      printf("+++ Heap write w/o base reg match: [%ld] MW: %s --> %lx (base reg %s --> 0x%lx)\n",
	     ins_num, info->mnemonic, addr, LynxReg2Str(base_reg), base_addr);

      printf("                   allocated by %s at %ld: start = 0x%lx, end = 0x%lx\n",
	     ainfo->alloc_fn, ainfo->ins_num, ainfo->start_addr, ainfo->end_addr);
    }
#endif
  }

  return 0;
}


/*******************************************************************************
 *                                                                             *
 * chk_heap_write() -- if the instruction writes to any heap-allocated memory, *
 * check whether the address written to is within bounds.                      *
 *                                                                             *
 *******************************************************************************/

void chk_heap_write(FnTracer_State *f_state, uint64_t ins_num, int tid) {
  InsInfo *info = f_state->ins_info;
  ReaderOp *op;
  int i;

  /*
   * destination operands: these are locations that are written to
   */
  op = info->dstOps;
  for (i = 0; i < info->dstOpCnt; i++) {
    if (op->type == MEM_OP && op->mem.base != LYNX_INVALID) {
      if (op_chk_OOB_heap_access(op, f_state, ins_num, tid)) {
	printf("@@@ OOB ACCESS: ins# %ld %s : addr accessed = 0%lx\n",
	       ins_num, info->mnemonic, op->mem.addr);
      }
    }
    op = op->next;
  }

  /*
   * read+wrote operands: these locations are both read and written to
   */
  op = info->readWriteOps;
  for(i = 0; i < info->readWriteOpCnt; i++) {
    if (op->type == MEM_OP && op->mem.base != LYNX_INVALID) {
      if (op_chk_OOB_heap_access(op, f_state, ins_num, tid)) {
	printf("@@@ OOB ACCESS: ins# %ld %s : addr accessed = 0%lx\n",
	       ins_num, info->mnemonic, op->mem.addr);
      }
    }
    op = op->next;
  }
  
}



