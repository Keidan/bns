#!/bin/bash

OTHER=""
if [ ! -z "${LD_LIBRARY_PATH}" ]; then
    OTHER=":${LD_LIBRARY_PATH}"
fi
export LD_LIBRARY_PATH=.${OTHER}
gdb --args ./bns ${*}
