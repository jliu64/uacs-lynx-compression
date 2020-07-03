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
 * alloc(n) -- return a pointer to a zero-initialized n-byte block of allocated memory
 * if possible; exit otherwise.
 * 
 */
void *alloc(int n) {
  void *ptr = calloc(n, 1);
  
  if (ptr == NULL) {
    msg(stderr, "Out of memory!");
    exit(1);
  }
  
  return ptr;
}



