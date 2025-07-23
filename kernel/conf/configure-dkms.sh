#!/bin/bash
# Auxiliary script for driver packaging

kernelver=$1
config=""

if [[ "$kernelver" == "3.10.0-"* ]] || [[ "$kernelver" == "4.9.0-"* ]]; then
    config="$config -DENABLE_CM_NO_BOUND_IF=1"
fi

if [[ "$kernelver" == "3.10.0-"* ]]; then
    config="$config -DDISABLE_VM_ACCESS=1"
fi

if [[ $ERDMA_LEGACY_MODE = "1" ]]; then
    config="$config -DENABLE_LEGACY_MODE=1"
fi

if [[ $ERDMA_CM_NO_BOUND_IF = "1" ]]; then
    config="$config -DENABLE_CM_NO_BOUND_IF=1"
fi

if [[ $ERDMA_FORCE_MAD_ENABLE = "1" ]]; then
    config="$config -DENABLE_MAD=1"
fi

mkdir -p build
pushd build
# Add path to fix the cmake is in /usr/local/bin
PATH=$PATH:/usr/local/bin cmake -DKERNEL_VER=${kernelver} .. ${config}
popd
