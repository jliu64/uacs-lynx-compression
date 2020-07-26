/*
 * File: utils.c
 * Purpose: various utility routines 
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include "utils.h"

/*
 * print a message on stream fp
 */
void stderrmsg(const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);

  vfprintf(stderr, fmt, args);
  fprintf(stderr, "\n");

  va_end(args);
}

/*
 * alloc(n) -- return a pointer to a zero-initialized n-byte block of allocated memory
 * if possible; exit otherwise.
 * 
 */
void *alloc(int n) {
  void *ptr = calloc(n, 1);
  
  if (ptr == NULL) {
    stderrmsg("Out of memory!");
    exit(1);
  }
  
  return ptr;
}


/*
 * get_unsigned() -- parse the argument string into an unsigned long value.  The
 * string is converted as follows: if it begins with '0x' it is treated as a
 * base-16 (hex) number; otherwise if it begins with '0' it is treated as a base-8
 * (octal) number; otherwise it is treated as a base-10 (decimal) number.
 */
uint64_t get_unsigned(char *str) {
  char *tail;
  uint64_t val;

  if (str == NULL) {
    stderrmsg("ERROR [%s]: NULL argument (aborting)\n", __func__);
    exit(1);
  }

  val = strtoul(str, &tail, 0);

  if (val <= 0) {
    stderrmsg("ERROR [%s]: invalid value %s (aborting)\n",
	      __func__, str);
    exit(1);
  }

  if (*tail != '\0') {  /* invalid input string */
    stderrmsg("ERROR [%s]: invalid characters in value: %s (aborting)\n",
	      __func__, tail);
    exit(1);
  }

  return val;
}

/*
 * swap: swap the two values pointed at
 */
void swap(uint64_t *val1, uint64_t *val2) {
  uint64_t tmp;
  tmp = *val1;
  *val1 = *val2;
  *val2 = tmp;
}
