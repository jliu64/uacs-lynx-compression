/*
 * File: print.h
 * Purpose: Information about code in print.c
 */

#ifndef __PRINT_H__
#define __PRINT_H__

#include "process_trace.h"

/*
 * print_usage() -- print out usage information
 */
void print_usage(char *exec_name);

/*
 * print_instr() -- print out an instruction
 */
void print_instr(CallInfo *csite, AllocationInfo *ainfo);

#endif  /* __PRINT_H__ */
