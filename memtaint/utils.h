/*
 * File: utils.h
 * Purpose: Information about code defined in utils.c
 */

#ifndef __UTILS_H_
#define __UTILS_H_

#include <stdint.h>

/*
 * stderrmsg() : print a message on stderr
 */
void stderrmsg(const char *fmt, ...);

/*
 * alloc(n) -- allocate a memory block of n bytes and return a pointer to the block.
 */
void *alloc(int n);

/*
 * get_unsigned() -- parse the argument string into an unsigned long value.  The
 * string is converted as follows: if it begins with '0x' it is treated as a
 * base-16 (hex) number; otherwise if it begins with '0' it is treated as a base-8
 * (octal) number; otherwise it is treated as a base-10 (decimal) number.
 */
uint64_t get_unsigned(char *str);

#endif  /* __UTILS_H_ */
