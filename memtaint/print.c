/*
 * File: print.c
 * Purpose: Output routines
 */

#include <assert.h>
#include <Reader.h>

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
  printf("  -m addr : introduce taint at memory address adr\n");
  printf("  -n num : introduce taint before event no. num\n");
  printf("  -d num : dump taint info before event no. num\n");
  printf("  -h : print usage\n");
  printf("  -i trace_file : read the instruction trace from file trace_file\n");
  printf("       (default: trace.out)\n");
}

