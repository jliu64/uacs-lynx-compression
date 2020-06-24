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
void msg(FILE *fp, const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);

  vfprintf(fp, fmt, args);
  fprintf(fp, "\n");

  va_end(args);
}

/*
 * alloc(n) -- allocate a memory block of n bytes and return a pointer to the block.
 */
void *alloc(int n) {
  void *ptr = malloc(n);
  
  if (ptr == NULL) {
    msg(stderr, "Out of memory!");
    exit(1);
  }
  
  return ptr;
}



