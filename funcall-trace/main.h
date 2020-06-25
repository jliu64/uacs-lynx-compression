/*
 * File: main.h
 * Purpose: Declarations common to the entire tool
 */

#ifndef __MAIN_H__
#define __MAIN_H__

#include <XedDisassembler.h>
#include <Reader.h>


typedef struct fntracer_state {
  xed_machine_mode_enum_t mmode;
  xed_address_width_enum_t stack_addr_width;
  char *trace_file;
  ReaderState *reader_state;
  InsInfo *ins_info;
  uint8_t has_src_id;
  uint8_t has_fn_id;
  uint8_t has_addr;
  uint8_t has_bin;
  uint8_t has_tid;
} FnTracer_State;





#endif  /* __MAIN_H__ */
