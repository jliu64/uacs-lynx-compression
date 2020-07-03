/*
 * File: allocator-info.c
 * Author: Saumya Debray (but we want to eventually generate this automatically)
 * Purpose: Information about argument and return types of allocator functions
 */

#include <stdio.h>
#include "allocator-info.h"
#include "parser.h"

AllocInfo allocator_info[] = {
  {"v8::internal::Heap::AllocateRaw",
   "$1",    /* $1 => allocation size is in argument 2 (arg1 is the self pointer) */
   NULL
  },
};


int n_allocfuns = sizeof(allocator_info)/sizeof(AllocInfo);

/*******************************************************************************
 *                                                                             *
 * init_alloc_info() -- initialize allocation information for allocation fns.  *
 *                                                                             *
 *******************************************************************************/

void init_alloc_info(FnTracer_State *f_state) {
  AllocInfo *a;
  int i;

  for (i = 0; i < n_allocfuns; i++) {
    a = &(allocator_info[i]);
    a->ast = parse(a->size_exp);
  }

  f_state->alloc_info = &(allocator_info[0]);
  f_state->n_allocfuns = n_allocfuns;
}
