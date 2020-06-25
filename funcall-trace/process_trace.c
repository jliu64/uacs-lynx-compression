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
 * call_list: a stack of CallsiteInfo structs that mimics the call stack.
 */
static CallsiteInfo *call_list = NULL;
static uint8_t instr_was_call = 0, instr_was_ret = 0;

/*******************************************************************************
 *                                                                             *
 *                                 PROTOTYPES                                  *
 *                                                                             *
 *******************************************************************************/

static void free_csite_info(uint64_t retsite_addr);

/*******************************************************************************
 *                                                                             *
 * get_next_event() -- get the next event, update prev_addr                    *
 *                                                                             *
 *******************************************************************************/

static uint32_t get_next_event(ReaderState *reader_state,
			ReaderEvent *curr_event,
			uint64_t *prev_addr) {
  if (curr_event != NULL && curr_event->type == INS_EVENT) {
    *prev_addr = curr_event->ins.addr;
  }

  return nextEvent(reader_state, curr_event);
}


/*******************************************************************************
 *                                                                             *
 * init_callsite_info() -- initialize callsite info for a call instruction.    *
 *                                                                             *
 *******************************************************************************/

static CallsiteInfo *init_callsite_info(FnTracer_State *f_state,
					ReaderIns *instr,
					uint64_t n) {
  CallsiteInfo *csite = alloc(sizeof(CallsiteInfo));
  int i;

  csite->ins_num = n;
  if (f_state->has_addr) {
    csite->callsite_addr = instr->addr;
    csite->retsite_addr = csite->callsite_addr + instr->binSize;
  }
  
  if (f_state->has_fn_id) {
    csite->caller_fn = strdup(fetchStrFromId(f_state->reader_state, instr->fnId));
  }
  
  csite->callee_fn = NULL;

  if (f_state->has_bin) {
    csite->ins_sz = instr->binSize;
    for (i = 0; i < instr->binSize; i++) {
      csite->ins_bytes[i] = instr->binary[i];
    }
    csite->mnemonic = strdup(f_state->ins_info->mnemonic);
  }

  return csite;
}


/*******************************************************************************
 *                                                                             *
 * proc_instr() -- process a single instruction                                *
 *                                                                             *
 *******************************************************************************/

static void proc_instr(FnTracer_State *f_state, ReaderIns *instr, uint64_t n) {
  xed_iclass_enum_t instr_op;
  CallsiteInfo *csite;

  /*
   * The name of the callee function is obtained as the function that the
   * instruction following the call instruction belongs to.  To indicate that
   * the previous instruction was a call, the variable instr_was_call is set 
   * to 1.  In this case, the entry at the top of the CallsiteInfo stack has
   * all the relevant fields except for the callee name filled in when the
   * call instruction (the instruction preceding this one) was processed.
   */
  if (instr_was_call != 0) {
    call_list->callee_fn = strdup(fetchStrFromId(f_state->reader_state, instr->fnId));
    print_instr(call_list);
  }
  instr_was_call = 0;
  
  if (instr_was_ret != 0) {
    free_csite_info(instr->addr);
    instr_was_ret = 0;
  }

  instr_op = f_state->ins_info->insClass;

  switch (instr_op) {
  case XED_ICLASS_CALL_FAR:
  case XED_ICLASS_CALL_NEAR:
    csite = init_callsite_info(f_state, instr, n);
    /*
     * add to global stack of CallsiteInfo structs
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
    instr_was_ret = 1;
    break;
    
  default:
    break;
  }

}

/*******************************************************************************
 *                                                                             *
 * proc_trace() -- read the trace and process its instructions                 *
 *                                                                             *
 *******************************************************************************/

void proc_trace(FnTracer_State *f_state) {
  uint64_t ins_num = 0;
  uint64_t prev_addr = 0, curr_addr = 0;
  ReaderEvent curr_event;

  while (get_next_event(f_state->reader_state, &curr_event, &prev_addr)) {
    if (curr_event.type == INS_EVENT) {
      fetchInsInfo(f_state->reader_state, &curr_event.ins, f_state->ins_info);
      curr_addr = curr_event.ins.addr;

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
 * free_csite_info() -- deallocate a CallsiteInfo structure.                   *
 *                                                                             *
 *******************************************************************************/

static void free_csite_info(uint64_t retsite_addr) {
  CallsiteInfo *ctmp, *ctmp_prev;
  uint64_t this_retsite_addr;
  
  for (ctmp = call_list; ctmp != NULL; ctmp = ctmp_prev) {
    ctmp_prev = ctmp->prev;
    this_retsite_addr = ctmp->retsite_addr;

    call_list = call_list->prev;
    if (call_list != NULL) {
      call_list->next = NULL;
    }
    
    free(ctmp->caller_fn);
    free(ctmp->callee_fn);
    free(ctmp->mnemonic);
    free(ctmp);

    if (this_retsite_addr == retsite_addr) {
      break;
    }
  }
}

