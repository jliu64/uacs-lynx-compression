/*
 * File: allocator-info.h
 * Purpose: Declarations and definitions pertaining to allocator-info.c
 */

#ifndef __ALLOCATOR_INFO_H__
#define __ALLOCATOR_INFO_H__

#include "main.h"
#include "parser.h"

/*
 * ArgType -- information about argument types used to print out their values
 */
typedef enum {
  SELF,       /* the "self-pointer" in OO language implementations */
  INT32_DEC,  /* int: decimal */
  INT32_HEX,  /* int: hex */
  INT64,      /* long */ 
  PTR         /* pointer */
} ArgType;


/*
 * AllocInfo stores information about how the allocation size request for an
 * allocator function should be computed (for many cases the valus is available
 * directly in an argument, but this is not universally true, e.g., for calloc).  
 * This information is specified in this data structure as a string, which is 
 * parsed into an AST by the parser in parser.c; the AST is subsequently 
 * evaluated when a call is encountered to determine the size requested.
 *
 * The expression grammar for argument values has the following rules, with the
 * usual operator associativities and precedences.  The notation $n is used to
 * specify the n^th argument to the function (starting at position 0), e.g., 
 * $2 represents argument 3.
 *
 *    expr ::=  expr + expr
 *          |   expr - expr       
 *          |   expr * expr
 *          |   expr / expr
 *          |   ( expr )
 *          |   int_const
 *          |   $n
 *
 * For example, the size expression for the library function calloc() would be
 * "$0 * $1".
 */
typedef struct alloc_info {
  char *fname;      /* function name */
  char *size_exp;   /* a string that gives the expression for the size request */
  TreeNode *ast;    /* the syntax tree for the size expression. */
} AllocInfo;


void init_alloc_info(FnTracer_State *f_state);

#endif  /* __ALLOCATOR_INFO_H__ */

