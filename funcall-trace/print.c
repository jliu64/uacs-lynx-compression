/*
 * File: print.c
 * Purpose: Output routines
 */

#include <assert.h>
#include <Reader.h>
#include <XedDisassembler.h>
#include "main.h"

/* 
 * INSTR_TXT_LEN -- assumed maximum length (in bytes) of the textual 
 * representation of an instruction
 */
#define INSTR_TXT_LEN  1024

/*
 * print_usage() -- print out usage information
 */
void print_usage(char *exec_name) {
  printf("Usage: %s [OPTIONS]\n", exec_name);
  printf("Options:\n");
  printf("  -h : print usage\n");
  printf("  -i trace_file : read the instruction trace from file trace_file\n");
}

/*
 * print_instr() -- print out an instruction
 */
void print_instr(FnTracer_State *f_state, ReaderEvent *instr, uint64_t ins_num) {
  printf("[%ld]", ins_num);

  if (f_state->has_addr) {
    printf(" 0x%llx;", (unsigned long long) instr->ins.addr);
  }

#if 0
  if (f_state->has_src_id) {
    printf(" %s;", fetchStrFromId(f_state->reader_state, instr->ins.srcId));
  }
#endif

  if (f_state->has_fn_id) {
    printf(" %s;", fetchStrFromId(f_state->reader_state, instr->ins.fnId));
  }

  if (f_state->has_bin) {
    int i;
    for (i = 0; i < instr->ins.binSize; i++) {
      printf(" %02x", instr->ins.binary[i]);
    }
	
    printf("; %s; ", f_state->ins_info->mnemonic);

  }

  printf("\n");

}



