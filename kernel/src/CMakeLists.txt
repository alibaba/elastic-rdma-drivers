# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
# Copyright 2021 Alibaba.com, Inc. All rights reserved
# Copyright 2021 Amazon.com, Inc. or its affiliates. All rights reserved.

list(APPEND erdma_sources
  erdma_eq.c erdma_cm.c erdma_cm.h erdma_cmdq.c erdma_cq.c
  erdma_debug.h erdma_hw.h erdma_ioctl.h
  erdma_ioctl.c erdma_main.c erdma_qp.c erdma_verbs.c
  erdma_verbs.h erdma-abi.h erdma.h erdma_cmdq.c kcompat.h
  erdma_stats.h erdma_stats.c
  )

string(REPLACE ";" " " erdma_sources_string "${erdma_sources}")
configure_file(Kbuild.in Kbuild @ONLY)

foreach(src ${erdma_sources})
  configure_file(${src} ${src} COPYONLY)
endforeach()

# Generate config.h
include(${CMAKE_SOURCE_DIR}/config/erdma.cmake)

if(ENABLE_CM_NO_BOUND_IF)
  message("-- ERDMA cm bound no IF")
  config_define(HAVE_SET_NON_SK_BOUND_IF)
endif()


set(module_cmd make -C ${KERNEL_DIR} M=${CMAKE_CURRENT_BINARY_DIR})

add_custom_command(OUTPUT erdma.ko
  COMMAND ${module_cmd} modules
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  DEPENDS ${erdma_sources} ${CMAKE_CURRENT_BINARY_DIR}/Kbuild ${CMAKE_CURRENT_BINARY_DIR}/config.h
  VERBATIM)

add_custom_target(modules ALL DEPENDS erdma.ko)
add_custom_target(modules_clean COMMAND ${module_cmd} clean)
