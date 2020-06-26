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
  printf("  -f fn_name : print call-return information about function fn_name\n");
  printf("       (this option may be repeated)\n");
  printf("  -h : print usage\n");
  printf("  -i trace_file : read the instruction trace from file trace_file\n");
  printf("       (default: trace.out)\n");
}

/*******************************************************************************
 *                                                                             *
 * print_instr() -- print out an instruction                                   *
 *                                                                             *
 *******************************************************************************/

void print_instr(CallInfo *csite) {
  char *starting_fn, *ending_fn;
  
  printf("[%ld] 0x%lx  ", csite->ins_num, csite->instr_addr);

  if (csite->ins_type == CALL) {
    starting_fn = csite->caller_fn;
    ending_fn = csite->callee_fn;
  }
  else {
    starting_fn = csite->callee_fn;
    ending_fn = csite->caller_fn;
  }
  
  if (starting_fn != NULL) {
    printf("%s :", starting_fn);
  }

  printf(" %s", csite->mnemonic);

  if (ending_fn != NULL) {
    printf(" -> %s", ending_fn);
  }

  if (csite->ins_type == RET && csite->callins_num != 0) {
    printf(" [@call_ins: %ld]", csite->callins_num);
  }
  printf("\n");
  /*
   * print argument/return values
   */
  if (csite->ins_type == CALL) {
    printf("\tARGUMENTS (assuming 4):\n");
    printf("\t#1 [%%rdi]: %s; #2 [%%rsi]: %s; #3 [%%rdx]: %s; #4 [%%rcx]: %s\n",
	   csite->args[0], csite->args[1], csite->args[2], csite->args[3]);
  }
  else {
    printf("\tRETURN VALUE [%%rax]: %s\n", csite->args[0]);
  }

  printf("\n");
}
