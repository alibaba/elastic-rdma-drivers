/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
 * Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.
 */

#ifndef SW_NET_H
#define SW_NET_H

#include <net/sock.h>
#include <net/if_inet6.h>
#include <linux/module.h>
#include "../kcompat.h"

struct sw_recv_sockets {
	struct socket *sk4;
	struct socket *sk6;
};

int sw_net_init(void);
void sw_net_exit(void);

#endif /* SW_NET_H */
