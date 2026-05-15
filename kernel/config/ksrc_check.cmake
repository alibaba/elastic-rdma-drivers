# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
# Copyright 2026 Alibaba.com, Inc.

# include(${CMAKE_SOURCE_DIR}/config/common.cmake)

function(kbuild_check_ib_uapi)
  set_conf_tmp_dir("#include <rdma/ib_user_ioctl_cmds.h>"
    "")
  execute_process(COMMAND make -C ${tmp_dir} KERNEL_DIR=${KERNEL_DIR} OFA_DIR=${OFA_DIR}
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    OUTPUT_QUIET ERROR_QUIET
    RESULT_VARIABLE res)
  if(res)
    message("-- Kbuild check: ib_user_ioctl_cmds.h is not available")
    set(HAVE_IB_USER_IOCTL_CMDS_H 0 CACHE INTERNAL "")
  else()
    message("-- Kbuild check: ib_user_ioctl_cmds.h is available")
    set(HAVE_IB_USER_IOCTL_CMDS_H 1 CACHE INTERNAL "")
  endif()
  # file(REMOVE_RECURSE ${CMAKE_CURRENT_BINARY_DIR}/${tmp_dir})
endfunction()


message("-- Checking RDMA UAPI ...")
kbuild_check_ib_uapi()
message("-- Checking RDMA UAPI - done")
