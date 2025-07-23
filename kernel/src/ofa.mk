# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
# Copyright 2023 Alibaba.com, Inc. All rights reserved

ifneq (${OFA_DIR},)
ifneq ($(shell test -d $(OFA_DIR) && echo "true" || echo "" ),)
	autoconf_h=$(shell /bin/ls -1 $(KERNEL_DIR)/include/*/autoconf.h 2> /dev/null | head -1)
	kconfig_h=$(shell /bin/ls -1 $(KERNEL_DIR)/include/*/kconfig.h 2> /dev/null | head -1)

	ifneq ($(kconfig_h),)
	KCONFIG_H = -include $(kconfig_h)
	endif

	OFAINCLUDE = -include $(autoconf_h) \
		$(KCONFIG_H) \
		-include $(OFA_DIR)/include/linux/compat-2.6.h \
		-I$(OFA_DIR)/include \
		-I$(OFA_DIR)/include/uapi/

	KBUILD_EXTRA_SYMBOLS=$(OFA_DIR)/Module.symvers
endif
endif