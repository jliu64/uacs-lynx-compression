# fncall_tracer -- tracing function calls and returns

## Description
This program extracts and prints out function calls and returns from a trace, together with argument values (for calls) and return values (for returns).

## Usage

    fncall_tracer [OPTIONS]

## Options
    -h : print usage
    -i trace_file : read the instruction trace from file trace_file

## Output
The output produced lists call and ret instructions in the trace in the order they appear.

The information produced for `call` instructions is:

    [NNN] 0xAAAAAAAA CALLER : INSTR -> CALLEE
        ARGUMENTS (assuming 4):
	#1 [%rdi]: xxxxxxxx; ...; #4 [%rcx]: xxxxxxxx

The information produced for `ret` instructions is:

    [NNN] 0xAAAAAAAA CALLEE : INSTR -> CALLER [@call_ins: MMM]
        RETURN VALUE [%rax]: xxxxxxxx

Here `NNN` is the position of the instruction in the trace; `AAAAAAAA` is its address; `CALLER` and `CALLEE` are the names of the caller and callee functions respectively; `INSTR` is the instruction; and `xxxxxxxx` are 64-bit hex values or the registers specified.  For `ret` instructions, the `@call_ins` field the position `MMM` of the matching `call` instruction.

## Improvements for the future
The tool can be improved in a number of ways, including:

1) Command-line options to select specific functions.
2) Some way to indicate the number and type of arguments taken by each function as well as the type of its return value (if any).

