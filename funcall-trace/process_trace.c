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
 * proc_instr() -- process a single instruction                                *
 *                                                                             *
 *******************************************************************************/

static void proc_instr(FnTracer_State *f_state, ReaderEvent *instr, uint64_t n) {
  xed_iclass_enum_t instr_op;
  uint8_t is_call = 0, is_ret = 0, print_ins = 0;

  instr_op = f_state->ins_info->insClass;

  switch (instr_op) {
  case XED_ICLASS_CALL_FAR:
  case XED_ICLASS_CALL_NEAR:
    print_ins = is_call = 1;
    break;

  case XED_ICLASS_RET_FAR:
  case XED_ICLASS_RET_NEAR:
  case XED_ICLASS_IRET:
  case XED_ICLASS_IRETD:
  case XED_ICLASS_IRETQ:
    print_ins = is_ret = 1;
    break;
  default:
    break;
  }

  if (print_ins) {
    print_instr(f_state, instr, n);
  }
}


/*******************************************************************************
 *                                                                             *
 * process_trace() -- read the trace and process its instructions              *
 *                                                                             *
 *******************************************************************************/

void process_trace(FnTracer_State *f_state) {
  uint64_t ins_num = 0;
  uint64_t prev_addr = 0, curr_addr = 0;
  ReaderEvent curr_event;
 
  while (get_next_event(f_state->reader_state, &curr_event, &prev_addr)) {
    if (curr_event.type == INS_EVENT) {
      fetchInsInfo(f_state->reader_state, &curr_event.ins, f_state->ins_info);
      curr_addr = curr_event.ins.addr;

      ins_num += 1;
      proc_instr(f_state, &curr_event, ins_num);
    }
    else if (curr_event.type == EXCEPTION_EVENT) {
      msg(stderr,
	  "EXCEPTION %d at %llx\n",
	  curr_event.exception.code,
	  (unsigned long long) curr_event.exception.addr);
    }
    else {
      printf("UNKNOWN EVENT TYPE\n");
    }
  }    /* while */
}


