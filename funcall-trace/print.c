/*
 * File: print.c
 * Purpose: Output routines
 */

#include <assert.h>
#include <Reader.h>
#include "process_trace.h"

/* 
 * INSTR_TXT_LEN -- assumed maximum length (in bytes) of the textual 
 * representation of an instruction
 */
#define INSTR_TXT_LEN  1024

/*******************************************************************************
 *                                                                             *
 * print_usage() -- print out usage information                                *
 *                                                                             *
 *******************************************************************************/

void print_usage(char *exec_name) {
  printf("Usage: %s [OPTIONS]\n", exec_name);
  printf("Options:\n");
  printf("  -h : print usage\n");
  printf("  -i trace_file : read the instruction trace from file trace_file\n");
}

/*******************************************************************************
 *                                                                             *
 * print_instr() -- print out an instruction                                   *
 *                                                                             *
 *******************************************************************************/

void print_instr(CallsiteInfo *csite) {
  printf("[%ld] 0x%llx %s ", csite->ins_num, csite->callsite_addr, csite->caller_fn);

  if (csite->ins_sz != 0) {
    for (int i = 0; i < csite->ins_sz; i++) {
      printf(" %02x", csite->ins_bytes[i]);
    }
	
    printf("; %s; ", csite->mnemonic);

  }

  if (csite->callee_fn != NULL) {
    printf(" -> %s;", csite->callee_fn);
  }
  
  printf("\n");

}
