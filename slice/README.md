# slice

This program computes a backward dynamic slice from a trace.

## Usage

    slicer [OPTIONS]

## Options
    -a addr : slice backwards starting from address addr (in base 16)
    -b fn_name : begin the trace at function fn_name
    -c : compress the block size in the dot file
    -e fn_name : end the trace at function fn_name
    -f fn_name : trace only the function fn_name
    -h : print usage
    -i trace_file : read the instruction trace from file trace_file
    -r : keep registers involved in taint calculations when loading from mem
    -s : generate cfg only from the given sources
    -S : make CFG with superblocks
    -t t_id : trace only the thread with id t_id (in base 10)
    -V : print slice validation info


## Output
The output produced by `slicer` lists the instructions in the backward dynamic slide one instruction per line.  Each line consists of a sequence of `;`-delimited fields in the following order:

    phase id
    function name
    instruction address;
    instruction mnemonic;

