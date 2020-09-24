#!bin/bash
cd "$(dirname "${BASH_SOURCE[0]}")"
export PIN=$(cd ../../../../ && pwd)
export TRACE2ASCII=$(cd trace2ascii && pwd)
export TRACER64=$(cd tracer/obj-intel64/ && pwd)
export TRACER32=$(cd tracer/obj-ia32/ && pwd)
cd -
