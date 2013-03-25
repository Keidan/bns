#!/bin/bash

ARCH="${1}"
if [[ -z "${ARCH}" ]]; then
  echo "Arch binary required!"
  exit 1
fi
if [[ ! -f "${ARCH}/bns" ]]; then
  echo "${ARCH}/bns not found!"
  exit 1
fi
shift
cd "${ARCH}"

OTHER=""
if [[ ! -z "${LD_LIBRARY_PATH}" ]]; then
    OTHER=":${LD_LIBRARY_PATH}"
fi
export LD_LIBRARY_PATH=.${OTHER}
./bns ${*}
