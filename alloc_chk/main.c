/*
 * File: main.c
 * Purpose: The driver code for the function call tracer tool
 * Author: Saumya Debray
 */

#include <stdio.h>
#include <string.h>
#include "allocator-info.h"
#include "main.h"
#include "print.h"
#include "process_trace.h"
#include "utils.h"

/*******************************************************************************
 *                                                                             *
 * parse_cmdline_args() -- parse command-line arguments and initialize various *
 * fields of f_state accordingly.                                              *
 *                                                                             *
 *******************************************************************************/

void parse_cmdline_args(int argc, char *argv[], FnTracer_State *f_state) {
  if (argc < 2) {
    print_usage(argv[0]);
    exit(1);
  }
  
  /*
   * Set up default arguments
   */
  f_state->trace_file = "trace.out";
  /*
   * parse command-line arguments
   */
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-i") == 0) {  /* -i : trace file name */
      f_state->trace_file = argv[++i];
      if (f_state->trace_file[0] == '-') {
	msg(stderr, "WARNING: Suspicious trace file name %s\n",	f_state->trace_file);
      }
    }
    else if (strcmp(argv[i], "-h") == 0) {
      print_usage(argv[0]);
      exit(0);
    }
    else if (strcmp(argv[i], "-c") == 0) {
      f_state->chk_heap = 1;
    }
    else if (argv[i][0] == '-') {
      msg(stderr, "Unrecognized option: %s\n", argv[i]);
    }
  }
}


/*******************************************************************************
 *                                                                             *
 * init_state() -- initialize the function call tracer's state                 *
 *                                                                             *
 *******************************************************************************/

FnTracer_State *init_state(int argc, char *argv[]) {
  FnTracer_State *f_state = alloc(sizeof(FnTracer_State));
  InsInfo *ins_info = alloc(sizeof(InsInfo));

  parse_cmdline_args(argc, argv, f_state);

  /* initialize XED tables */
  xed_tables_init();
  f_state->mmode = XED_MACHINE_MODE_LONG_64;
  f_state->stack_addr_width = XED_ADDRESS_WIDTH_64b;

  /* initialize f_state fields */
  f_state->reader_state = initReader(f_state->trace_file, 0);
  f_state->ins_info = ins_info;
  initInsInfo(f_state->ins_info);

  f_state->has_src_id = hasFields(f_state->reader_state, getSelMask(SEL_SRCID));
  f_state->has_fn_id = hasFields(f_state->reader_state, getSelMask(SEL_FNID));
  f_state->has_addr = hasFields(f_state->reader_state, getSelMask(SEL_ADDR));
  f_state->has_bin = hasFields(f_state->reader_state, getSelMask(SEL_BIN));
  f_state->has_tid = hasFields(f_state->reader_state, getSelMask(SEL_TID));

  /* initialize allocator function list */
  init_alloc_info(f_state);

  if (f_state->alloc_info == NULL) {
    msg(stderr, "No allocator functions specified.  Exiting.\n");
    exit(1);
  }

  return f_state;
}


/*******************************************************************************
 *                                                                             *
 * The main driver routine                                                     *
 *                                                                             *
 *******************************************************************************/

int main(int argc, char *argv[]) {
  FnTracer_State *f_state = init_state(argc, argv);
  proc_trace(f_state);

  return 0;
}
