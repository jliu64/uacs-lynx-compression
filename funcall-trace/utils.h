/*
 * File: utils.h
 * Purpose: Information about code defined in utils.c
 */

#ifndef __UTILS_H_
#define __UTILS_H_

/*
 * print a message on stream fp
 */
void msg(FILE *fp, const char *fmt, ...);

/*
 * alloc(n) -- allocate a memory block of n bytes and return a pointer to the block.
 */
void *alloc(int n);


#endif  /* __UTILS_H_ */
