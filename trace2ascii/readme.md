# Trace2Ascii

In this directory, we have a very simple tool that will use the reader to print a human-readable representation of the trace to stdout.

## Build
1. Build the Reader Library
2. Run 'make'

## Usage

Because the trace is being printed to standard out, we recomend that trace2ascii be executed as follows:

`trace2ascii [trace] > [file]`

Where trace is a valid trace from the tracer and file is the file to store the output.

## Example

`trace2ascii trace.out > ascii.out`
