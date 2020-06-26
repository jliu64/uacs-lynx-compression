# fncall_tracer -- tracing function calls and returns

## Description
This program extracts and prints out function calls and returns from a trace, together with argument values (for calls) and return values (for returns).

## Usage

    fncall_tracer [OPTIONS]

## Options
    -f fn_name : print call-return information about function fn_name.  (This option may be repeated.)
    -h : print usage
    -i trace_file : read the instruction trace from file trace_file.  If not specified, trace_file defaults to `trace.out`.

## Output
The output produced lists call and ret instructions in the trace in the order they appear.

The information produced for `call` instructions is:

    [NNN] 0xAAAAAAAA CALLER : INSTR -> CALLEE
        ARGUMENTS (assuming 4):
	#1 [%rdi]: xxxxxxxx; ...; #4 [%rcx]: xxxxxxxx

The information produced for `ret` instructions is:

    [NNN] 0xAAAAAAAA CALLEE : INSTR -> CALLER [@call_ins: MMM]
        RETURN VALUE [%rax]: xxxxxxxx

Here `NNN` is the position of the instruction in the trace; `AAAAAAAA` is its address; `CALLER` and `CALLEE` are the names of the caller and callee functions respectively; `INSTR` is the instruction; and `xxxxxxxx` are 64-bit hex values or the registers specified.  For `ret` instructions, the `@call_ins` field gives the position `MMM` of the matching `call` instruction.

## Example
The output generated from the command `fncall_tracer -i examples/factorial/trace.out -f fact -f main`:

```
[1017] 0x7fa5495c282e  __libc_start_main : call rax -> main
	ARGUMENTS (assuming 4):
	#1 [%rdi]: 0000000000000002; #2 [%rsi]: 00007fff76070448; #3 [%rdx]: 00007fff76070460; 
#4 [%rcx]: 0000000000000000

[1825] 0x4005e1  main : call 0xffffffffffffff85 -> fact
	ARGUMENTS (assuming 4):
	#1 [%rdi]: 0000000000000006; #2 [%rsi]: 0000000000000006; #3 [%rdx]: 0000000000000000; 
#4 [%rcx]: 00007fff76070cc2

[1835] 0x400586  fact : call 0xffffffffffffffe0 -> fact
	ARGUMENTS (assuming 4):
	#1 [%rdi]: 0000000000000005; #2 [%rsi]: 0000000000000006; #3 [%rdx]: 0000000000000000; 
#4 [%rcx]: 00007fff76070cc2

[1845] 0x400586  fact : call 0xffffffffffffffe0 -> fact
	ARGUMENTS (assuming 4):
	#1 [%rdi]: 0000000000000004; #2 [%rsi]: 0000000000000006; #3 [%rdx]: 0000000000000000; 
#4 [%rcx]: 00007fff76070cc2

[1855] 0x400586  fact : call 0xffffffffffffffe0 -> fact
	ARGUMENTS (assuming 4):
	#1 [%rdi]: 0000000000000003; #2 [%rsi]: 0000000000000006; #3 [%rdx]: 0000000000000000; 
#4 [%rcx]: 00007fff76070cc2

[1865] 0x400586  fact : call 0xffffffffffffffe0 -> fact
	ARGUMENTS (assuming 4):
	#1 [%rdi]: 0000000000000002; #2 [%rsi]: 0000000000000006; #3 [%rdx]: 0000000000000000; 
#4 [%rcx]: 00007fff76070cc2

[1875] 0x400586  fact : call 0xffffffffffffffe0 -> fact
	ARGUMENTS (assuming 4):
	#1 [%rdi]: 0000000000000001; #2 [%rsi]: 0000000000000006; #3 [%rdx]: 0000000000000000; 
#4 [%rcx]: 00007fff76070cc2

[1885] 0x400590  fact : ret  -> fact [@call_ins: 1875]
	RETURN VALUE [%rax]: 0000000000000001

[1888] 0x400590  fact : ret  -> fact [@call_ins: 1865]
	RETURN VALUE [%rax]: 0000000000000002

[1891] 0x400590  fact : ret  -> fact [@call_ins: 1855]
	RETURN VALUE [%rax]: 0000000000000006

[1894] 0x400590  fact : ret  -> fact [@call_ins: 1845]
	RETURN VALUE [%rax]: 0000000000000018

[1897] 0x400590  fact : ret  -> fact [@call_ins: 1835]
	RETURN VALUE [%rax]: 0000000000000078

[1900] 0x400590  fact : ret  -> main [@call_ins: 1825]
	RETURN VALUE [%rax]: 00000000000002d0

[63421] 0x400606  main : ret  -> __libc_start_main [@call_ins: 1017]
	RETURN VALUE [%rax]: 0000000000000000

```

## Improvements for the future
The tool can be improved in a number of ways, including:

1) Some way to indicate the number and type of arguments taken by each function as well as the type of its return value (if any).

