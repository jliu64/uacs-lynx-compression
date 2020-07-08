# Using the Trace Reader: A Tutorial

This document provides a high-level introduction to the trace reader.  It is not intended to be a detailed and exhaustive exposition of the trace reader API; for this, please see the README file and the source code.

## Trace files
A trace file is a binary file that consists of a header followed by a sequence of *events*.  Each event represents either a normal instruction execution or else an exception.  The reader provides information about each event to the client application using the reader.

## Processing an execution trace
To process an execution trace, we first initialize the reader state, then repeatedly fetch and process execution events.  In most cases, the client application will need to disassemble and analyze the instructions that are executed.  It can do this using Intel's [XED](https://intelxed.github.io/) disassembler.  The code to do this has the structure shown below.  The types `ReaderState` and `ReaderEvent` are defined in the file `reader/Reader.h`.  It is the client's responsibility to allocate space for a `ReaderEvent` structure and pass a pointer to it to `nextEvent()`, which fills in its fields.


``` C
#include <XedDisassembler.h>
#include <Reader.h>

void process_trace() {
  ReaderState *reader_state;
  ReaderEvent curr_event;
  InsInfo ins_info;
  xed_machine_mode_enum_t mmode;
  xed_address_width_enum_t stack_addr_width;

  char *trace_file = ... ;    /* name of trace file */
  
  /* initialize the reader */
  reader_state = initReader(trace_file, 0);

  /* initialize XED tables */
  xed_tables_init();
  mmode = XED_MACHINE_MODE_LONG_64;
  stack_addr_width = XED_ADDRESS_WIDTH_64b;

  /* process the trace */
  while (nextEvent(reader_state, &curr_event)) {
    if (curr_event.type == INS_EVENT) {
       ...  /* normal execution */
    }
    else if (curr_event.type == EXCEPTION_EVENT) {
       ...  /* exception */
    }
    else {
      ...   /* unrecognized event type */
    }
  }    /* while */
  
  closeReader(reader_state);
}
```
The value `XED_ADDRESS_WIDTH_64b` indicates that stack addresses are 64 bits wide; for 32-bit addresses use `XED_ADDRESS_WIDTH_32b`.


## Accessing information about the execution
The trace reader maintains information about the program's execution state as execution progresses.  This information is updated at each execution event, and can be accessed by the client analyses.

Information about an execution can be divided into the following categories:

1) Global summary information about the execution.
2) The execution state of the program (memory and register values).
3) Properties of each executed instruction.

We discuss each of these categories in the following sections.

### Global summary information

The total number of threads created during an execution can be obtained using

``` C
uint32_t getNumThreads(ReaderState *state)
```

### Memory and register values

The trace reader maintains a shadow architecture to track memory and register values through execution; see files `ShadowMemory.[ch]` and `ShadowRegisters.[ch]`.  Register and memory values can be accessed using

``` C
const uint8_t *getRegisterVal(ReaderState *state, LynxReg reg, uint32_t thread);
void getMemoryVal(ReaderState *state, uint64_t addr, uint32_t size, uint8_t *buf);
```

Here, `LynxReg` refers to an enumeration of x86-64 registers used by this toolset.  It is defined in the file `.../shared/LynxReg.h`.

**Note:**

1) `getRegisterVal()` returns a string representation of the value of the register. This can be converted to a binary representation using `strtoul()` if necessary.
2) `getMemoryVal()` expects the buffer `buf` to be large enough to store the value of the memory region specified; this is not checked.
3) For each event in a trace, the shadow architecture provides the execution state *immediately before* that event.  To obtain information about the execution state after an event, use the state associated with (i.e., just before) the next event in the trace.

### Properties of instructions
To improve space efficiency, information about instructions is split into two data structures, `InsInfo` and `ReaderIns`, that are defined in the file `Reader.h`.

- `InsInfo` contains information that is invariant across all occurrences of an instruction in a program.  Examples include: the source and destination operands, the textual representation of the instruction, etc.
- `ReaderIns` contains information that may be different for different occurrences of an instruction in a program.  Examples include: the binary encoding of the instruction, its address in memory, (information about) the function it belongs to, etc.

The `InsInfo` data structure is not updated automatically when `nextEvent()` is called (this is to make it possible to access the program's execution state after an event).  It is processed as follows (see the README file for details):

- **Initialization**:
  `void initInsInfo(InsInfo *info)`
- **Update**:
  `int fetchInsInfo(ReaderState *state, ReaderIns *ins, InsInfo *info)`

For example, client code to print out the address and mnemonic of each executed instruction would be something like the following (code shown earlier, e.g., to initialize XED, is omited to reduce clutter):

``` C
  /* initialize the reader */
  ReaderState reader_state = initReader(trace_file, 0);
  InsInfo info;
  initInsInfo(&info);

  /* process the trace */
  while (nextEvent(reader_state, &curr_event)) {
    if (curr_event.type == INS_EVENT) {    /* normal execution */
      fetchInsInfo(readerState, &curr_event.ins, &info);
      printf("ADDR: 0x%lx  INSTR: %s\n", curr_event.ins.addr, info.mnemonic);
    }
  }
```

