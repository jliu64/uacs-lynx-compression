/*
 * File: print.h
 * Purpose: Information about code in print.c
 */

#ifndef __PRINT_H__
#define __PRINT_H__

#include <Reader.h>
#include "main.h"

/*
 * print_usage() -- print out usage information
 */
void print_usage(char *exec_name);

/*
 * print_instr() -- print out an instruction
 */
void print_instr(FnTracer_State *f_state, ReaderEvent *instr, uint64_t ins_num);

#endif  /* __PRINT_H__ */
