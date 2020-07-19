# memtaint -- a simple memory taint forward-propagation tool

## Description
This program is intended to demonstrate how to use the taint library for forward taint propagation.

## Usage

    memtaint [OPTIONS]

## Options
- <code>-i *trace_file*</code> : read the instruction trace from file <code>*trace_file*</code>.  If not specified, <code>*trace_file*</code> defaults to <code>**trace.out**</code>.
    
- <code>-n *num*</code> : introduce taint at the point just before instruction no. <code>*num*</code> in the trace.  If no instruction number is specified, it defaults to 0.  <code>*num*</code> is converted to a numerical value using the library function `strtoul()` and so follows the lexical conventions used by that function.
    
- <code>-m *addr*</code> : introduce taint at memory address <code>*addr*</code>.  <code>*addr*</code> is converted to a numerical value using the library function `strtoul()` and so follows the lexical conventions used by that function.  Taint is introduced at the locations specified just before the instruction no. specified in the most recent `-n` option (defaults to 0 if no `-n` is specified).  This option may be repeated.  Currently the tool taints only the 4-byte word at <code>*addr*</code>.

- <code>-d *num*</code> : dump information about tainted locations (registers + memory) at the point just before instruction no. <code>*num*</code> in the trace.  <code>*num*</code> is converted to a numerical value using the library function `strtoul()` and so follows the lexical conventions used by that function.

- `-h` : print usage

**Note:** For the `-d` and `-n` options, instruction numbers begin at 0.  The `trace2ascii` tool can be used to get instruction numbers in the trace.

## Output
The output currently simply lists all tainted locations (registers and memory) after each instruction in the trace.  This can and should be improved.


## Example
The following invocation of this tool processes the trace file `mytrace.out`; introduces taint at the 4-byte word at addresses `0x10000` and `0x12000` just before instruction `537` in the trace, and at address `0x14000` just before instruction `1643` in the trace; and dumps taint information just before instruction `1845` in the trace:

    memtaint -i mytrace.out -n 537 -m 0x10000 -m 0x12000 -n 1643 -m 0x14000 -d 1845


## Improvements for the future
The tool can be improved in a number of ways, including:

1) More flexibility in introducing taint.  E.g., registers as well as memory, control how big a block of memory should be tainted; maybe inputs to or outputs from specific functions;
2) The ability to have different locations (reg/mem) get different taint labels;
3) Controlling what is done with taint.


