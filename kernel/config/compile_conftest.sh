#!/bin/bash
# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
# Copyright 2021 Amazon.com, Inc. or its affiliates. All rights reserved.

tmpdir=$1
kerneldir=$2

if [ $# -eq 4 ]; then
	success=$3
	fail=$4
	make -C $tmpdir KERNEL_DIR=$kerneldir >/dev/null 2>$tmpdir/output.log
else
	success=$4
	fail=$5

	make -C $tmpdir KERNEL_DIR=$kerneldir OFA_DIR=$3 >/dev/null 2>$tmpdir/output.log
fi

err=$?

if [[ "$err" -eq 0 ]] && [[ -n "$success" ]]; then
	echo "#define $success 1" >> config.h
fi

if [[ "$err" -ne 0 ]] && [[ -n "$fail" ]]; then
	echo "#define $fail 1" >> config.h
fi

cat $tmpdir/output.log >> ../output.log
rm -fr $tmpdir
