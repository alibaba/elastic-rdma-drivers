# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
# Copyright 2021 Alibaba.com, Inc. All rights reserved
# Copyright 2021 Amazon.com, Inc. or its affiliates. All rights reserved.

list(APPEND erdma_sources
  erdma_eq.c erdma_cm.c erdma_cm.h erdma_cmdq.c erdma_cq.c
  erdma_hw.h erdma_ioctl.h erdma_compat.h erdma_compat.c
  erdma_ioctl.c erdma_main.c erdma_qp.c erdma_verbs.c
  erdma_verbs.h erdma-abi.h erdma.h erdma_cmdq.c kcompat.h
  erdma_stats.h erdma_stats.c erdma_debugfs.c erdma_cmd.c
  )

if(ENABLE_MAD)
  list(APPEND erdma_sources 
  compat/sw.h compat/sw_hw_counters.h compat/sw_net.h compat/sw_param.h compat/sw_queue.h compat/sw_verbs.h
  compat/sw_hdr.h compat/sw_loc.h compat/sw_opcode.h compat/sw_pool.h compat/sw_task.h compat/rdma_user_sw.h
  compat/sw_av.c compat/sw_cq.c compat/sw_icrc.c compat/sw_net.c compat/sw_pool.c compat/sw_queue.c compat/sw_comp.c
  compat/sw_dev.c compat/sw_mcast.c compat/sw_mr.c compat/sw_opcode.c compat/sw_qp.c compat/sw_recv.c
  compat/sw_verbs.c compat/sw_req.c compat/sw_task.c compat/sw_resp.c
  )
endif()

string(REPLACE ";" " " erdma_sources_string "${erdma_sources}")
configure_file(Kbuild.in Kbuild @ONLY)
configure_file(ofa.mk ofa.mk COPYONLY)

foreach(src ${erdma_sources})
  configure_file(${src} ${src} COPYONLY)
endforeach()

# Generate config.h
include(${CMAKE_SOURCE_DIR}/config/erdma.cmake)

if(ENABLE_CM_NO_BOUND_IF)
  message("-- ERDMA cm bound no IF")
  config_define(HAVE_SET_NON_SK_BOUND_IF)
endif()

if(DISABLE_VM_ACCESS)
  message("-- Disable VM access")
  config_define(DISABLE_VM_ACCESS)
endif()

if(ENABLE_MAD)
  message("-- ERDMA RoCE MAD enabled")
  config_define(HAVE_ERDMA_MAD)
else()
  message("-- ERDMA RoCE MAD disabled")
endif()

if(ENABLE_LEGACY_MODE)
  message("-- ERDMA legacy mode enabled")
  config_define(HAVE_LEGACY_MODE_BY_DEFAULT)
else()
  message("-- ERDMA legacy mode disabled")
endif()

set(module_cmd make -C ${KERNEL_DIR} M=${CMAKE_CURRENT_BINARY_DIR} OFA_DIR=${OFA_DIR} KERNEL_DIR=${KERNEL_DIR} )

add_custom_command(OUTPUT erdma.ko
  COMMAND ${module_cmd} modules
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  DEPENDS ${erdma_sources} ${CMAKE_CURRENT_BINARY_DIR}/Kbuild ${CMAKE_CURRENT_BINARY_DIR}/ofa.mk ${CMAKE_CURRENT_BINARY_DIR}/config.h
  VERBATIM)

add_custom_target(modules ALL DEPENDS erdma.ko)
add_custom_target(modules_clean COMMAND ${module_cmd} clean)
