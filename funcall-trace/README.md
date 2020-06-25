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

Here `NNN` is the position of the instruction in the trace; `AAAAAAAA` is its address; `CALLER` and `CALLEE` are the names of the caller and callee functions respectively; `INSTR` is the instruction; and `xxxxxxxx` are 64-bit hex values or the registers specified.  For `ret` instructions, the `@call_ins` field gives the position `MMM` of the matching `call` instruction.

## Example
A slice of the output from a trace of the luaJIT program:

```
[12349] 0x4063b0  luaL_error : call 0x1a880 -> luaL_openlibs
	ARGUMENTS (assuming 4):
	#1 [%rdi]: 0000000040a3f378; #2 [%rsi]: 0000000000000000; #3 [%rdx]: 0000000000000000; 
#4 [%rcx]: 0000000000000015

[12362] 0x420c4e  luaL_openlibs : call qword ptr [rbp+0x10] -> lua_dump
	ARGUMENTS (assuming 4):
	#1 [%rdi]: 0000000040a3f010; #2 [%rsi]: 0000000000000000; #3 [%rdx]: 0000000000000000; 
#4 [%rcx]: 0000000000000015

[12413] 0x417be6  lua_dump : ret  -> luaL_openlibs [@call_ins: 12362]
	RETURN VALUE [%rax]: 0000000040a41550

[12423] 0x420c6a  luaL_openlibs : ret  -> luaL_error [@call_ins: 12349]
	RETURN VALUE [%rax]: 0000000040a41550
```

## Improvements for the future
The tool can be improved in a number of ways, including:

1) Command-line options to select specific functions.
2) Some way to indicate the number and type of arguments taken by each function as well as the type of its return value (if any).

