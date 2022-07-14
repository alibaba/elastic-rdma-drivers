# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
# Copyright 2020 Amazon.com, Inc. or its affiliates. All rights reserved.

DRIVER_NAME = conftest
KBUILD_CPPFLAGS += -Werror -Wno-unused-variable -Wno-uninitialized -Wno-maybe-uninitialized

ifneq (${LINUXINCLUDE},)
LINUXINCLUDE := \
	-I/usr/src/ofa_kernel/default/include \
	-I/usr/src/ofa_kernel/default/include/uapi/ \
	${LINUXINCLUDE}
endif

KBUILD_EXTRA_SYMBOLS=/usr/src/ofa_kernel/default/Module.symvers

obj-m += $(DRIVER_NAME).o
$(DRIVER_NAME)-objs := main.o

KERNEL_DIR ?= /lib/modules/$(shell uname -r)/build

modules:
	$(MAKE) -C $(KERNEL_DIR) M=$(CURDIR) modules
