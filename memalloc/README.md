# alloc_chk -- track and check heap allocations and heap accesses

## Description
This program tracks heap allocations and monitors heap accesses for out-of-bound (OOB) writes.

## Usage

    alloc_chk [OPTIONS]

## Options
- `-c` : check heap accesses.  Checks each heap write to see whether it is based off a previously allocated heap region, and if so whether the address written falls within the bounds of the allocated region.  **NOTE: Currently not fully implemented.**
- `-h` : print usage
- <code>-i *trace_file*</code> : read the instruction trace from file <code>*trace_file*</code>.  If not specified, <code>*trace_file*</code> defaults to <code>**trace.out**</code>.

## Output
Information about heap allocations is printed out as follows:

   [nnn]  allocator   allocation_size  -->  start_addr -- end_addr

where:

- `nnn` is the instruction number (i.e., position in the trace) of the call to the allocator ;
- `allocator` is the name of the allocation function;
- `allocation_size` is the size (in bytes) of the allocated memory region; and
- `start_addr` and `end_addr` are the start and end addresses of the memory region returned by the allocator.

For example, the following refers to a heap allocation of 16 bytes by the function `v8::internal::Heap::AllocateRaw`.  The function was called by the instruction at position 5268586 in an execution trace.  The memory region allocated starts at address `0x263ae6082228` and ends at address `0x263ae6082237`:

    [5268586] v8::internal::Heap::AllocateRaw  16  --> 0x263ae6082228 -- 0x263ae6082237

## Allocator functions
This tool checks only functions that it knows to be heap allocation functions; currently it is necessary to specify the set of allocation functions recognized, and for each such function how the size of the allocation region should be obtained.

### Specifying allocator functions
Each allocator function is specified as an array consisting of two strings: (1) the name of the function, and (2) an expression specifying how the size of the allocation region should be computed:

``` C
typedef struct alloc_info {
  char *fname;      /* function name */
  char *size_exp;   /* a string that gives the expression for the size request */
  TreeNode *ast;    /* the syntax tree for the size expression. */
} AllocInfo;
```

The third field, `*ast`, should initially be given as `NULL`; it is filled in later by code that parses the expression `size_exp` and constructs an abstract syntax tree for it.  See the file <code>**allocator-info.h**</code> for more information about the syntax of size expressions.

The set of allocator functions to be tracked is specified as an array

```
AllocInfo allocator_info[] = {
    { ... info for allocator function 1... }
    { ... info for allocator function 2... }
    ...
};
```

For example:

``` C
AllocInfo allocator_info[] = {
  {"v8::internal::Heap::AllocateRaw",
   "$1",    /* $1 => allocation size is in argument 2 (arg1 is the self pointer) */
   NULL
  },
  {"calloc",
   "$0 * $1",
   NULL
  },
};
```

## System identification

Heap management code is highly system-dependent.  Different systems have different heap allocation functions and may handle tagged pointers differently.  We can indicate system-specific code snippets using macros such as:

``` C
#define SYSTEM_IS_V8    /* the analysis will follow V8 specifics */
```

For example, the current implementation flags system-specific handling of tagged pointers as

``` C
uint64_t untag(uint64_t ptr) {
#ifdef SYSTEM_IS_V8
  return (ptr & ~(0x1UL));
#endif    /* SYSTEM_IS_V8 */

  return ptr;    /* default: do nothing */
}
```

## Tracking heap allocations and checking heap accesses

The tool currently constructs a linked list of heap-allocated regions that can be accessed from the variable `alloc_info` defined in the file `process_trace.c`.  When a new allocation is found, information about the allocation is added to the front of this list.  The tool currently does not know about deallocation routines, so deallocated memory regions are not removed from this list.

Heap writes are checked using the function `chk_heap_write()`.  This checking is performed if the comand-line option `-c` is specified.


