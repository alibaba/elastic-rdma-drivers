#!/bin/bash
# Auxiliary script for driver packaging

kernelver=$1
config=""

if [[ "$kernelver" == "3.10.0-"* ]] || [[ "$kernelver" == "4.9.0-"* ]]; then
    config="$config -DENABLE_CM_NO_BOUND_IF=1"
fi

mkdir -p build
pushd build
cmake -DKERNEL_VER=${kernelver} .. ${config}
popd
