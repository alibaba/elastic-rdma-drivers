/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
 * Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.
 */

#ifndef SW_H
#define SW_H

#ifdef pr_fmt
#undef pr_fmt
#endif
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/crc32.h>

#include <rdma/ib_verbs.h>
#include <rdma/ib_user_verbs.h>
#include <rdma/ib_pack.h>
#include <rdma/ib_smi.h>
#include <rdma/ib_umem.h>
#include <rdma/ib_cache.h>
#include <rdma/ib_addr.h>
#include <crypto/hash.h>

#include "sw_net.h"
#include "sw_opcode.h"
#include "sw_hdr.h"
#include "sw_param.h"
#include "sw_verbs.h"
#include "sw_loc.h"

#include "../erdma.h"
/*
 * Version 1 and Version 2 are identical on 64 bit machines, but on 32 bit
 * machines Version 2 has a different struct layout.
 */
#define SW_UVERBS_ABI_VERSION		2

#define SW_ROCE_V2_SPORT		(0xc000)

extern bool sw_initialized;

static inline u32 sw_crc32(struct sw_dev *sw,
			    u32 crc, void *next, size_t len)
{
	u32 retval;
	int err;

	SHASH_DESC_ON_STACK(shash, sw->tfm);

	shash->tfm = sw->tfm;
	*(u32 *)shash_desc_ctx(shash) = crc;
	err = crypto_shash_update(shash, next, len);
	if (unlikely(err)) {
		pr_warn_ratelimited("failed crc calculation, err: %d\n", err);
		return crc32_le(crc, next, len);
	}

	retval = *(u32 *)shash_desc_ctx(shash);
	barrier_data(shash_desc_ctx(shash));
	return retval;
}

void sw_set_mtu(struct sw_dev *sw, unsigned int dev_mtu);

int sw_add(struct sw_dev *sw, unsigned int mtu, const char *ibdev_name);

void sw_rcv(struct sk_buff *skb);

/* The caller must do a matching ib_device_put(&dev->ib_dev) */
static inline struct sw_dev *sw_get_dev_from_net(struct net_device *ndev)
{
	struct ib_device *ibdev;
	struct erdma_dev *dev;

	ibdev = ib_device_get_by_netdev(ndev, RDMA_DRIVER_ERDMA);
	if (!ibdev) {
		pr_err_ratelimited("ib_device_get_by_netdev non");
		return NULL;
	}

	dev = container_of(ibdev, struct erdma_dev, ibdev);
	return &dev->sw_dev;
}

void sw_port_up(struct sw_dev *sw);
void sw_port_down(struct sw_dev *sw);
void sw_set_port_state(struct sw_dev *sw);

#endif /* SW_H */
