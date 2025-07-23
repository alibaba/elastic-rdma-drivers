# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
# Copyright 2022 Alibaba.com, Inc. All rights reserved
# Copyright 2021 Amazon.com, Inc. or its affiliates. All rights reserved.

cmake_minimum_required(VERSION 2.8.12)
project(erdma C)

set(KERNEL_VER "" CACHE STRING "Kernel version to build for")
if(NOT KERNEL_VER)
  execute_process(COMMAND uname -r OUTPUT_VARIABLE uname_r
                  OUTPUT_STRIP_TRAILING_WHITESPACE)
  set(KERNEL_VER ${uname_r})
  set(KERNEL_DIR "/lib/modules/${uname_r}/build")
else()
  set(KERNEL_DIR "/lib/modules/${KERNEL_VER}/build")
endif()

unset(KERNEL_MAKEFILE CACHE)
find_file(KERNEL_MAKEFILE Makefile PATHS ${KERNEL_DIR} NO_DEFAULT_PATH)
if(NOT KERNEL_MAKEFILE)
  message(FATAL_ERROR "No kernel Makefile")
endif()

set(OFA_DIR "" CACHE STRING "OFA path to build for")
unset(OFA_SYM_VER CACHE)
unset(OFA_SYM_DEF CACHE)

find_file(OFA_SYM_VER Module.symvers PATHS /usr/src/ofa_kernel/${KERNEL_VER} NO_DEFAULT_PATH)
find_file(OFA_SYM_DEF Module.symvers PATHS /usr/src/ofa_kernel/default NO_DEFAULT_PATH)

if (OFA_SYM_VER)
  message("-- ${KERNEL_VER} out-of-tree OFA found - use this OFA")
  set(OFA_DIR "/usr/src/ofa_kernel/${KERNEL_VER}")
  set(ENABLE_MAD "True")
elseif (OFA_SYM_DEF)
  message("-- Default out-of-tree OFA found - use this OFA")
  set(OFA_DIR "/usr/src/ofa_kernel/default")
  set(ENABLE_MAD "True")
else ()
  message("-- No out-of-tree OFA found - use in-tree OFA")
  set(OFA_DIR "")
endif()

message("-- Kernel directory - ${KERNEL_DIR}")

add_subdirectory(src)