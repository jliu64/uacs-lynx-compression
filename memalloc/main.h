/*
 * File: main.h
 * Purpose: Declarations common to the entire tool
 */

#ifndef __MAIN_H__
#define __MAIN_H__

#include <XedDisassembler.h>
#include <Reader.h>

/*******************************************************************************
 *                                                                             *
 *                      GLOBAL CONSTANTS AND DEFINITIONS                       *
 *                                                                             *
 *******************************************************************************/

#define SYSTEM_IS_V8    /* the analysis will follow V8 specifics */


/*******************************************************************************
 *                                                                             *
 *                             STRUCT DEFINITIONS                              *
 *                                                                             *
 *******************************************************************************/

typedef struct fntracer_state {
  xed_machine_mode_enum_t mmode;
  xed_address_width_enum_t stack_addr_width;
  char *trace_file;
  char chk_heap;
  struct alloc_info *alloc_info;    /* array of allocation fn info */
  int n_allocfuns;          /* no. of allocation functions */
  ReaderState *reader_state;
  InsInfo *ins_info;
  uint8_t has_src_id;
  uint8_t has_fn_id;
  uint8_t has_addr;
  uint8_t has_bin;
  uint8_t has_tid;
} FnTracer_State;

#endif  /* __MAIN_H__ */
