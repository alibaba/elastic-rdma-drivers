# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
# Copyright 2022 Alibaba.com, Inc. All rights reserved
# Copyright 2021 Amazon.com, Inc. or its affiliates. All rights reserved.

cmake_minimum_required(VERSION 2.8.11)
project(erdma C)

set(KERNEL_VER "" CACHE STRING "Kernel version to build for")
if(NOT KERNEL_VER)
  execute_process(COMMAND uname -r OUTPUT_VARIABLE uname_r
                  OUTPUT_STRIP_TRAILING_WHITESPACE)
  set(KERNEL_DIR "/lib/modules/${uname_r}/build")
else()
  set(KERNEL_DIR "/lib/modules/${KERNEL_VER}/build")
endif()

unset(KERNEL_MAKEFILE CACHE)
find_file(KERNEL_MAKEFILE Makefile PATHS ${KERNEL_DIR} NO_DEFAULT_PATH)
if(NOT KERNEL_MAKEFILE)
  message(FATAL_ERROR "No kernel Makefile")
endif()
message("-- Kernel directory - ${KERNEL_DIR}")

add_subdirectory(src)