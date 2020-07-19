/*
 * File: main.c
 * Purpose: Top-level driver for the taint analysis tool
 * Author: Saumya Debray
 */

#include <stdio.h>
#include <string.h>
#include <Taint.h>

#include "main.h"
#include "print.h"
#include "process_trace.h"
#include "utils.h"

/*******************************************************************************
 *                                                                             *
 * parse_cmdline_args() -- parse command-line arguments and initialize various *
 * fields of m_state accordingly.                                              *
 *                                                                             *
 *******************************************************************************/

void parse_cmdline_args(int argc, char *argv[], MemTaint_State *m_state) {
  uint64_t event_num = 0;
  /*
   * Set up default arguments
   */
  m_state->trace_file = "trace.out";
  /*
   * parse command-line arguments
   */
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-i") == 0) {  /* -i : trace file name */
      m_state->trace_file = argv[++i];
      if (m_state->trace_file[0] == '-') {
	stderrmsg("WARNING: Suspicious trace file name %s\n",	m_state->trace_file);
      }
    }
    else if (strcmp(argv[i], "-m") == 0) {    /* mem addr to taint (4 bytes for now) */
      uint64_t start = get_unsigned(argv[++i]);
      Taint_Loc *taint_addrs = alloc(sizeof(Taint_Loc));
      taint_addrs->start = start;
      taint_addrs->sz = 4;    /* <<< FIXME: NEED TO GENERALIZE! */
      taint_addrs->ins_num = event_num;

      /* add this to the list of taint locations in m_state */
      taint_addrs->next = m_state->taint_loc;
      m_state->taint_loc = taint_addrs;      
    }
    else if (strcmp(argv[i], "-n") == 0) {    /* event no. */
      event_num = get_unsigned(argv[++i]);
    }
    else if (strcmp(argv[i], "-d") == 0) {    /* dump taint */
      Dump_Taint *dump_info = alloc(sizeof(Dump_Taint));
      dump_info->ins_num = get_unsigned(argv[++i]);

      /* add this to the list of dump locations */
      dump_info->next = m_state->dump_info;
      m_state->dump_info = dump_info;
    }
    else if (strcmp(argv[i], "-h") == 0) {
      print_usage(argv[0]);
      exit(0);
    }
    else if (argv[i][0] == '-') {
      stderrmsg("Unrecognized option: %s\n", argv[i]);
    }
  }
}


/*******************************************************************************
 *                                                                             *
 * init_state() -- initialize the function call tracer's state                 *
 *                                                                             *
 *******************************************************************************/

MemTaint_State *init_state(int argc, char *argv[]) {
  MemTaint_State  *m_state = alloc(sizeof(MemTaint_State));
  InsInfo *ins_info = alloc(sizeof(InsInfo));

  parse_cmdline_args(argc, argv, m_state);

  if (m_state->taint_loc == NULL) {
    stderrmsg("No locations specified for initial taint... exiting\n");
    exit(1);
  }

  /* initialize XED tables */
  xed_tables_init();
  m_state->mmode = XED_MACHINE_MODE_LONG_64;
  m_state->stack_addr_width = XED_ADDRESS_WIDTH_64b;

  /* initialize m_state fields */
  m_state->reader_state = initReader(m_state->trace_file, 0);
  m_state->taint_state = initTaint(m_state->reader_state);
  m_state->ins_info = ins_info;
  initInsInfo(m_state->ins_info);

  m_state->has_src_id = hasFields(m_state->reader_state, getSelMask(SEL_SRCID));
  m_state->has_fn_id = hasFields(m_state->reader_state, getSelMask(SEL_FNID));
  m_state->has_addr = hasFields(m_state->reader_state, getSelMask(SEL_ADDR));
  m_state->has_bin = hasFields(m_state->reader_state, getSelMask(SEL_BIN));
  m_state->has_tid = hasFields(m_state->reader_state, getSelMask(SEL_TID));

  return m_state;
}


/*******************************************************************************
 *                                                                             *
 * The main driver routine                                                     *
 *                                                                             *
 *******************************************************************************/

int main(int argc, char *argv[]) {
  MemTaint_State  *m_state = init_state(argc, argv);

  proc_trace(m_state);

  return 0;
}
