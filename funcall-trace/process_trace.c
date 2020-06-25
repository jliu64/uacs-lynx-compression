/*
 * File: process_trace.c
 * Purpose: Process an execution trace and print out function call/return info.
 * Author: Saumya Debray
 */

#include <stdio.h>
#include <string.h>
#include "main.h"
#include "print.h"
#include "utils.h"

/*
 * call_list: a stack of CallInfo structs that mimics the call stack.
 */
static CallInfo *call_list = NULL;
static CallInfo *ret_info;
static uint8_t instr_was_call = 0, instr_was_ret = 0;

/*******************************************************************************
 *                                                                             *
 *                                 PROTOTYPES                                  *
 *                                                                             *
 *******************************************************************************/

static void free_csite_info(uint64_t retsite_addr);
static CallInfo *find_call_info(uint64_t retsite_addr);

/*******************************************************************************
 *                                                                             *
 * init_call_info() -- initialize info for a call instruction.                 *
 *                                                                             *
 *******************************************************************************/

static CallInfo *init_call_info(FnTracer_State *f_state,
				ReaderIns *instr,
				uint64_t n) {
  CallInfo *csite = alloc(sizeof(CallInfo));

  csite->ins_type = CALL;
  csite->callins_num = csite->ins_num = n;  
    
  if (f_state->has_addr) {
    csite->instr_addr = instr->addr;
    csite->retsite_addr = csite->instr_addr + instr->binSize;
  }
  
  if (f_state->has_fn_id) {
    csite->caller_fn = strdup(fetchStrFromId(f_state->reader_state, instr->fnId));
  }
  
  csite->callee_fn = NULL;

  if (f_state->has_bin) {
#if 0
    csite->ins_sz = instr->binSize;
    for (int i = 0; i < instr->binSize; i++) {
      csite->ins_bytes[i] = instr->binary[i];
    }
#endif
    csite->mnemonic = strdup(f_state->ins_info->mnemonic);
  }

  return csite;
}


/*******************************************************************************
 *                                                                             *
 * init_ret_info() -- initialize info for a ret instruction.                   *
 *                                                                             *
 *******************************************************************************/

static void init_ret_info(FnTracer_State *f_state,
			  ReaderIns *instr,
			  uint64_t n) {
  ret_info->ins_num = n;

  if (f_state->has_addr) {
    ret_info->instr_addr = instr->addr;
    ret_info->retsite_addr = 0;
  }
  
  ret_info->caller_fn = NULL;
  if (f_state->has_fn_id) {
    ret_info->callee_fn = strdup(fetchStrFromId(f_state->reader_state, instr->fnId));
  }

  if (f_state->has_bin) {
#if 0
    csite->ins_sz = instr->binSize;
    for (int i = 0; i < instr->binSize; i++) {
      csite->ins_bytes[i] = instr->binary[i];
    }
#endif
    ret_info->mnemonic = strdup(f_state->ins_info->mnemonic);
  }
}


/*******************************************************************************
 *                                                                             *
 * proc_instr() -- process a single instruction                                *
 *                                                                             *
 *******************************************************************************/

static void proc_instr(FnTracer_State *f_state, ReaderIns *instr, uint64_t n) {
  xed_iclass_enum_t instr_op;
  CallInfo *csite;

  /*
   * The name of the callee function is obtained as the function that the
   * instruction following the call instruction belongs to.  To indicate that
   * the previous instruction was a call, the variable instr_was_call is set 
   * to 1.  In this case, the entry at the top of the CallInfo stack has
   * all the relevant fields except for the callee name filled in when the
   * call instruction (the instruction preceding this one) was processed.
   */
  if (instr_was_call != 0) {
    call_list->callee_fn = strdup(fetchStrFromId(f_state->reader_state, instr->fnId));
    print_instr(call_list);
  }
  instr_was_call = 0;
  
  if (instr_was_ret != 0) {
    ret_info->caller_fn = strdup(fetchStrFromId(f_state->reader_state, instr->fnId));
    csite = find_call_info(instr->addr);
    if (csite != NULL) {
      ret_info->callins_num = csite->ins_num;
    }
    print_instr(ret_info);

    free_csite_info(instr->addr);
    instr_was_ret = 0;
  }

  instr_op = f_state->ins_info->insClass;

  switch (instr_op) {
  case XED_ICLASS_CALL_FAR:
  case XED_ICLASS_CALL_NEAR:
    csite = init_call_info(f_state, instr, n);
    /*
     * add to global stack of CallInfo structs
     */
    csite->prev = call_list;
    if (call_list != NULL) {
      call_list->next = csite;
    }
    call_list = csite;
    instr_was_call = 1;
    break;

  case XED_ICLASS_RET_FAR:
  case XED_ICLASS_RET_NEAR:
  case XED_ICLASS_IRET:
  case XED_ICLASS_IRETD:
  case XED_ICLASS_IRETQ:
    init_ret_info(f_state, instr, n);
    instr_was_ret = 1;
    break;
    
  default:
    break;
  }

}

/*******************************************************************************
 *                                                                             *
 * find_call_info() -- given a return address, return a pointer to the         *
 * corresponding call the CallInfo stack, if one exists; NULL otherwise.       *
 *                                                                             *
 *******************************************************************************/
  
static CallInfo *find_call_info(uint64_t retsite_addr) {
CallInfo *ctmp;
  for (ctmp = call_list; ctmp != NULL; ctmp = ctmp->prev) {
    if (ctmp->retsite_addr == retsite_addr) {
      return ctmp;
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

  ret_info = alloc(sizeof(CallInfo));  /* initialize for RET instrs in the trace */
  ret_info->ins_type = RET;            /* initialize for RET instrs in the trace */

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
 * free_csite_info() -- deallocate a CallInfo structure.                   *
 *                                                                             *
 *******************************************************************************/

static void free_csite_info(uint64_t retsite_addr) {
  CallInfo *ctmp, *ctmp_prev;
  uint64_t this_retsite_addr;
  /*
   * Check whether the return address appears on the CallInfo stack (it may not, 
   * e.g., in the case of a ROP sequence).
   */
  if (find_call_info(retsite_addr) == NULL) {
    printf("WARNING: return address 0x%lx not found on call stack\n", retsite_addr);
    return;
  }
  /*
   * retsite_addr appears on the call stack.  Pop the call stack up to and
   * including the corresponding call site.
   */
  for (ctmp = call_list; ctmp != NULL; ctmp = ctmp_prev) {
    ctmp_prev = ctmp->prev;
    this_retsite_addr = ctmp->retsite_addr;

    call_list = call_list->prev;
    if (call_list != NULL) {
      call_list->next = NULL;
    }
    
    if (ctmp->caller_fn != NULL) free(ctmp->caller_fn);
    if (ctmp->callee_fn != NULL) free(ctmp->callee_fn);
    if (ctmp->mnemonic != NULL) free(ctmp->mnemonic);
    free(ctmp);

    if (this_retsite_addr == retsite_addr) {
      break;
    }
  }
}

