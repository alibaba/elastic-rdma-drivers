# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
# Copyright 2026 Alibaba.com, Inc.
# Copyright 2021 Amazon.com, Inc. or its affiliates. All rights reserved.

# include_guard(GLOBAL)

function(set_conf_tmp_dir prologue body)
  string(RANDOM rand)
  set(tmp_dir "tmp_${rand}")
  set(tmp_dir ${tmp_dir} PARENT_SCOPE)
  configure_file(${CMAKE_SOURCE_DIR}/config/main.c.in ${tmp_dir}/main.c @ONLY)
  configure_file(${CMAKE_SOURCE_DIR}/config/Makefile ${tmp_dir} COPYONLY)
  configure_file(${CMAKE_SOURCE_DIR}/src/ofa.mk ${tmp_dir} COPYONLY)
endfunction()

