# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
# Copyright 2020 Amazon.com, Inc. or its affiliates. All rights reserved.

DRIVER_NAME = conftest
KBUILD_CPPFLAGS += -Werror -Wno-unused-variable -Wno-uninitialized -Wno-maybe-uninitialized

KERNEL_DIR ?= /lib/modules/$(shell uname -r)/build

ifeq ($(src),)
        src=.
endif
include $(src)/ofa.mk

ifneq (${LINUXINCLUDE},)
LINUXINCLUDE := \
	${OFAINCLUDE} \
	${LINUXINCLUDE}
endif

obj-m += $(DRIVER_NAME).o
$(DRIVER_NAME)-objs := main.o

modules:
	$(MAKE) -C $(KERNEL_DIR) M=$(CURDIR) modules
