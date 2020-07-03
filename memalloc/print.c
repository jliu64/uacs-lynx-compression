/*
 * File: print.c
 * Purpose: Output routines
 */

#include <assert.h>
#include <Reader.h>
#include "allocator-info.h"
#include "process_trace.h"
#include "utils.h"

/*******************************************************************************
 *                                                                             *
 *                        Calling-convention information                       *
 *                                                                             *
 *******************************************************************************/

extern LynxReg arg_regs[];


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
  printf("       (default: trace.out)\n");
}

/*******************************************************************************
 *                                                                             *
 * print_instr() -- print out an instruction                                   *
 *                                                                             *
 *******************************************************************************/

void print_instr(CallInfo *csite, AllocationInfo *ainfo) {
  printf("[%ld] %s  %d  --> 0x%lx -- 0x%lx\n",
	 ainfo->ins_num,
	 ainfo->alloc_fn,
	 ainfo->size,
	 ainfo->start_addr,
	 ainfo->end_addr);
}
