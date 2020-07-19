/*
 * File: process_trace.c
 * Purpose: Process an execution trace and print out taint info.
 * Author: Saumya Debray
 */

#include <assert.h>
#include <stdio.h>
#include "main.h"
#include "print.h"
#include "utils.h"

/*******************************************************************************
 *                                                                             *
 *                                 PROTOTYPES                                  *
 *                                                                             *
 *******************************************************************************/
static void add_taint(MemTaint_State *m_state, uint64_t int_num);
static void dump_taint(MemTaint_State *m_state, uint64_t ins_num);

/*******************************************************************************
 *                                                                             *
 * proc_instr() -- process a single instruction                                *
 *                                                                             *
 *******************************************************************************/

void proc_instr(MemTaint_State *m_state, ReaderEvent *curr_event, uint64_t ins_num) {
  ReaderIns *instr = &(curr_event->ins);

  fetchInsInfo(m_state->reader_state, instr, m_state->ins_info);

  add_taint(m_state, ins_num);    /* introduce taint where appropriate */

  dump_taint(m_state, ins_num);   /* print taint state if appropriate */

  propagateForward(m_state->taint_state, curr_event, m_state->ins_info, 0);

}

/*******************************************************************************
 *                                                                             *
 * proc_trace() -- read the trace and process its instructions                 *
 *                                                                             *
 *******************************************************************************/

void proc_trace(MemTaint_State *m_state) {
  uint64_t ins_num = 0;
  ReaderEvent curr_event;

  while (nextEvent(m_state->reader_state, &curr_event)) {
    if (curr_event.type == INS_EVENT) {
      proc_instr(m_state, &curr_event, ins_num);
      ins_num++;
    }
    else if (curr_event.type == EXCEPTION_EVENT) {
      stderrmsg("EXCEPTION %d at %llx\n",
		curr_event.exception.code,
		(unsigned long long) curr_event.exception.addr);
    }
    else {
      stderrmsg("UNKNOWN EVENT TYPE\n");
    }
  }    /* while */

  printf("----- final -----\n");
  outputTaint(m_state->taint_state);
}


/*******************************************************************************
 *                                                                             *
 * add_taint() -- for each Taint_Loc whose ins_num matches the argument, add   *
 * taint at address start.                                                     *
 *                                                                             *
 *******************************************************************************/

static void add_taint(MemTaint_State *m_state, uint64_t ins_num) {
  Taint_Loc *t_loc;
  uint64_t t_label;

  for (t_loc = m_state->taint_loc; t_loc != NULL; t_loc = t_loc->next) {
    if (t_loc->ins_num == ins_num) {
      t_label = getNewLabel(m_state->taint_state);
      printf("ADDING TAINT: ins#: %ld, taint loc: 0x%lx, taint label: 0x%lx\n", ins_num, t_loc->start, t_label);
      taintMem(m_state->taint_state, t_loc->start, t_loc->sz, t_label);
    }
  }
}


/*******************************************************************************
 *                                                                             *
 * dump_taint() -- if ins_num matches any value in the dump_locs field of the  *
 * taint state, print out all the tainted locations.                           *
 *                                                                             *
 *******************************************************************************/

static void dump_taint(MemTaint_State *m_state, uint64_t ins_num) {
  Dump_Taint *d_info;

  for (d_info = m_state->dump_info; d_info != NULL; d_info = d_info->next) {
    if (d_info->ins_num == ins_num) {
      printf("TAINT STATE AT ins# %ld:\n", ins_num);
      outputTaint(m_state->taint_state);
      printf("----------\n");
    }
  }
}
