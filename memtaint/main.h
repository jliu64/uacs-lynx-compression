/*
 * File: main.h
 * Purpose: Declarations common to the entire tool
 */

#ifndef __MAIN_H__
#define __MAIN_H__

#include <XedDisassembler.h>
#include <Reader.h>
#include <Taint.h>

/*
 * The Taint_Loc struct holds information about a memory word that should
 * be tainted during execution.  Its fields are as follows:
 *
 *    ins_num: introduce taint immediately before event ins_num occurs
 *        in the trace;
 *    start: the start address in memory to be tainted;
 *    sz : the no. of bytes to be tainted
 *    next: pointer to the next node in the linked list
 */
typedef struct taint_loc {
  uint64_t ins_num;  
  uint64_t start;
  int sz;
  struct taint_loc *next;
} Taint_Loc;

/*
 * Dump_taint stores information about when taint information should be output.
 */
typedef struct dump_taint {
  uint64_t ins_num;
  struct dump_taint *next;
} Dump_Taint;

typedef struct memtaint_state {
  xed_machine_mode_enum_t mmode;
  xed_address_width_enum_t stack_addr_width;
  char *trace_file;
  ReaderState *reader_state;
  TaintState *taint_state;
  Taint_Loc *taint_loc;
  Dump_Taint *dump_info;
  InsInfo *ins_info;
  uint8_t has_src_id;
  uint8_t has_fn_id;
  uint8_t has_addr;
  uint8_t has_bin;
  uint8_t has_tid;
} MemTaint_State;

#endif  /* __MAIN_H__ */
