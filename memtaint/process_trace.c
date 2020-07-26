/*
 * File: process_trace.c
 * Purpose: Process an execution trace and print out taint info.
 * Author: Saumya Debray
 */

#include <assert.h>
#include <stdint.h>
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
static void init_taint_params(MemTaint_State *m_state);

static uint64_t tins_ctr = UINTMAX_MAX, tdump_ctr = UINTMAX_MAX;

/*******************************************************************************
 *                                                                             *
 * proc_instr() -- process a single instruction                                *
 *                                                                             *
 *******************************************************************************/

void proc_instr(MemTaint_State *m_state, ReaderEvent *curr_event, uint64_t ins_num) {
  ReaderIns *instr = &(curr_event->ins);

  fetchInsInfo(m_state->reader_state, instr, m_state->ins_info);

  if (tins_ctr == 0) {
    add_taint(m_state, ins_num);    /* introduce taint where appropriate */
  }

  if (tdump_ctr == 0) {
    dump_taint(m_state, ins_num);   /* print taint state if appropriate */
  }

  propagateForward(m_state->taint_state, curr_event, m_state->ins_info, 0);

  tins_ctr--; tdump_ctr--;
}

/*******************************************************************************
 *                                                                             *
 * proc_trace() -- read the trace and process its instructions                 *
 *                                                                             *
 *******************************************************************************/

void proc_trace(MemTaint_State *m_state) {
  uint64_t ins_num = 0;
  ReaderEvent curr_event;

  init_taint_params(m_state);

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
  uint64_t t_label, next;

  for (t_loc = m_state->taint_loc; t_loc != NULL; t_loc = t_loc->next) {
    if (t_loc->ins_num == ins_num) {
      t_label = getNewLabel(m_state->taint_state);
      printf("ADDING TAINT: ins#: %ld, taint loc: 0x%lx, taint label: 0x%lx\n", ins_num, t_loc->start, t_label);
      taintMem(m_state->taint_state, t_loc->start, t_loc->sz, t_label);
    }
  }
  /*
   * reset the counter to the no. of instructions to the next taint addition
   */
  next = UINTMAX_MAX;
  for (t_loc = m_state->taint_loc; t_loc != NULL; t_loc = t_loc->next) {
    if (t_loc->ins_num <= ins_num) {
      continue;
    }
    next = t_loc->ins_num - ins_num;
    break;
  }
  tins_ctr = next;
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

/*******************************************************************************
 *                                                                             *
 * init_taint_params() -- sort the lists for adding and dumping taint, and     *
 * initialize the corresponding global counters.                               *
 *                                                                             *
 *******************************************************************************/

static void init_taint_params(MemTaint_State *m_state) {
  Taint_Loc *tloc_i, *tloc_j;
  Dump_Taint *dloc_i, *dloc_j;
  /*
   * sort the lists of taint insertion and taint dump locations.  For the big-O 
   * police: this is not where the program spends its time.
   */
  for (tloc_i = m_state->taint_loc; tloc_i != NULL; tloc_i = tloc_i->next) {
    for (tloc_j = tloc_i->next; tloc_j != NULL; tloc_j = tloc_j->next) {
      if (tloc_i->ins_num > tloc_j->ins_num) {
	swap(&(tloc_i->ins_num), &(tloc_j->ins_num));
	swap(&(tloc_i->start), &(tloc_j->start));
	swap(&(tloc_i->sz), &(tloc_j->sz));
      }
    }
  }

  for (dloc_i = m_state->dump_info; dloc_i != NULL; dloc_i = dloc_i->next) {
    for (dloc_j = dloc_i->next; dloc_j != NULL; dloc_j = dloc_j->next) {
      if (dloc_i->ins_num > dloc_j->ins_num) {
	swap(&(dloc_i->ins_num), &(dloc_j->ins_num));
      }
    }
  }

  /*
   * initialize the counters for introducing and dumping taint
   */
  if (m_state->taint_loc != NULL) {
    tins_ctr = m_state->taint_loc->ins_num;
  }

  if (m_state->dump_info != NULL) {
    tdump_ctr = m_state->dump_info->ins_num;
  }
}
