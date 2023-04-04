/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */

/* Authors: Cheng Xu <chengyou@linux.alibaba.com> */
/*          Kai Shen <kaishen@linux.alibaba.com> */
/* Copyright (c) 2020-2022, Alibaba Group. */

/*
 * Copyright 2018-2021 Amazon.com, Inc. or its affiliates. All rights reserved.
 */

#ifndef __KCOMPAT_H__
#define __KCOMPAT_H__

#include <linux/pci.h>
#include <linux/types.h>
#include "config.h"

#define ERDMA_MAJOR_VER 0
#define ERDMA_MEDIUM_VER 2
#define ERDMA_MINOR_VER 35

#include <rdma/ib_verbs.h>
#ifndef RDMA_DRIVER_ERDMA
#define RDMA_DRIVER_ERDMA 19
#endif

#if !defined(HAVE_RDMA_UMEM_FOR_EACH_DMA_BLOCK) &&                             \
	defined(HAVE_IB_UMEM_FIND_SINGLE_PG_SIZE)
#include <rdma/ib_umem.h>

static inline void __rdma_umem_block_iter_start(struct ib_block_iter *biter,
						struct ib_umem *umem,
						unsigned long pgsz)
{
	__rdma_block_iter_start(biter, umem->sg_head.sgl, umem->nmap, pgsz);
}

/**
 * rdma_umem_for_each_dma_block - iterate over contiguous DMA blocks of the umem
 * @umem: umem to iterate over
 * @pgsz: Page size to split the list into
 *
 * pgsz must be <= PAGE_SIZE or computed by ib_umem_find_best_pgsz(). The
 * returned DMA blocks will be aligned to pgsz and span the range:
 * ALIGN_DOWN(umem->address, pgsz) to ALIGN(umem->address + umem->length, pgsz)
 *
 * Performs exactly ib_umem_num_dma_blocks() iterations.
 */
#define rdma_umem_for_each_dma_block(umem, biter, pgsz)                        \
	for (__rdma_umem_block_iter_start(biter, umem, pgsz);                  \
	     __rdma_block_iter_next(biter);)
#endif

#ifdef HAVE_U32_PORT
typedef u32 port_t;
#else
typedef u8 port_t;
#endif

#ifndef HAVE_IB_PORT_PHYS_STATE_LINK_UP
#define IB_PORT_PHYS_STATE_DISABLED 3
#define IB_PORT_PHYS_STATE_LINK_UP 5
#endif

#ifndef HAVE_IBDEV_PRINT
#define ibdev_err(_ibdev, format, arg...)                                      \
	dev_err(&((struct ib_device *)(_ibdev))->dev, format, ##arg)
#define ibdev_dbg(_ibdev, format, arg...)                                      \
	dev_dbg(&((struct ib_device *)(_ibdev))->dev, format, ##arg)
#define ibdev_warn(_ibdev, format, arg...)                                     \
	dev_warn(&((struct ib_device *)(_ibdev))->dev, format, ##arg)
#define ibdev_info(_ibdev, format, arg...)                                     \
	dev_info(&((struct ib_device *)(_ibdev))->dev, format, ##arg)
#endif

#ifndef HAVE_CORE_MMAP_XA
#include <linux/types.h>
#include <linux/device.h>

struct rdma_user_mmap_entry {
	struct ib_ucontext *ucontext;
	unsigned long start_pgoff;
	size_t npages;
};

/* Return the offset (in bytes) the user should pass to libc's mmap() */
static inline u64
rdma_user_mmap_get_offset(const struct rdma_user_mmap_entry *entry)
{
	return (u64)entry->start_pgoff << PAGE_SHIFT;
}

/*
 * Backported kernels don't keep refcnt on entries, hence they should not
 * be removed.
 */
static inline void
rdma_user_mmap_entry_remove(struct rdma_user_mmap_entry *entry)
{
}

static inline void rdma_user_mmap_entry_put(struct rdma_user_mmap_entry *entry)
{
}
#endif

#ifndef HAVE_IB_PORT_PHYS_STATE_LINK_UP
#define IB_PORT_PHYS_STATE_DISABLED 3
#define IB_PORT_PHYS_STATE_LINK_UP 5
#endif

#include <rdma/ib_verbs.h>
#ifndef ibdev_err
#define ibdev_err(_ibdev, format, arg...)                                      \
	dev_err(&((struct ib_device *)(_ibdev))->dev, format, ##arg)
#endif
#ifndef ibdev_dbg
#define ibdev_dbg(_ibdev, format, arg...)                                      \
	dev_dbg(&((struct ib_device *)(_ibdev))->dev, format, ##arg)
#endif
#ifndef ibdev_warn
#define ibdev_warn(_ibdev, format, arg...)                                     \
	dev_warn(&((struct ib_device *)(_ibdev))->dev, format, ##arg)
#endif
#ifndef ibdev_info
#define ibdev_info(_ibdev, format, arg...)                                     \
	dev_info(&((struct ib_device *)(_ibdev))->dev, format, ##arg)
#endif

#ifndef ibdev_err_ratelimited
#define ibdev_err_ratelimited(_ibdev, format, arg...)                          \
	dev_err_ratelimited(&((struct ib_device *)(_ibdev))->dev, format, ##arg)
#endif
#ifndef ibdev_dbg_ratelimited
#define ibdev_dbg_ratelimited(_ibdev, format, arg...)                          \
	dev_dbg_ratelimited(&((struct ib_device *)(_ibdev))->dev, format, ##arg)
#endif
#ifndef ibdev_warn_ratelimited
#define ibdev_warn_ratelimited(_ibdev, format, arg...)                         \
	dev_warn_ratelimited(&((struct ib_device *)(_ibdev))->dev, format,     \
			     ##arg)
#endif
#ifndef ibdev_info_ratelimited
#define ibdev_info_ratelimited(_ibdev, format, arg...)                         \
	dev_info_ratelimited(&((struct ib_device *)(_ibdev))->dev, format,     \
			     ##arg)
#endif

#include <rdma/rdma_user_cm.h>
#ifndef RDMA_MAX_PRIVATE_DATA
#define RDMA_MAX_PRIVATE_DATA 256
#endif

#include <net/sock.h>
#include <linux/tcp.h>

#ifndef HAVE_TCP_SOCK_SET_NODELAY

static inline int tcp_sock_set_nodelay(struct sock *sk)
{
	mm_segment_t oldfs;
	int rv, val = 1;

	oldfs = get_fs();

	set_fs(KERNEL_DS);

	rv = sk->sk_prot->setsockopt(sk, SOL_TCP, TCP_NODELAY,
				     (char __user *)&val, sizeof(val));
	set_fs(oldfs);
	return rv;
}
#endif

#ifndef HAVE_SOCK_SET_REUSEADDR
static inline void sock_set_reuseaddr(struct sock *sk)
{
	lock_sock(sk);
	sk->sk_reuse = SK_CAN_REUSE;
	release_sock(sk);
}
#endif

#ifndef HAVE_ETHERDEVICE_HELPER
static inline void u64_to_ether_addr(u64 u, u8 *addr)
{
	int i;

	for (i = ETH_ALEN - 1; i >= 0; i--) {
		addr[i] = u & 0xff;
		u = u >> 8;
	}
}

static inline void addrconf_addr_eui48_base(u8 *eui, const char *const addr)
{
	memcpy(eui, addr, 3);
	eui[3] = 0xFF;
	eui[4] = 0xFE;
	memcpy(eui + 5, addr + 3, 3);
}

static inline void addrconf_addr_eui48(u8 *eui, const char *const addr)
{
	addrconf_addr_eui48_base(eui, addr);
	eui[0] ^= 2;
}
#endif

#ifndef HAVE_IB_MTU_INT_TO_ENUM
static inline enum ib_mtu ib_mtu_int_to_enum(int mtu)
{
	if (mtu >= 4096)
		return IB_MTU_4096;
	else if (mtu >= 2048)
		return IB_MTU_2048;
	else if (mtu >= 1024)
		return IB_MTU_1024;
	else if (mtu >= 512)
		return IB_MTU_512;
	else
		return IB_MTU_256;
}
#endif

#ifdef HAVE_HEADER_LINUX_SCHED_SIGNAL
#include <linux/sched/signal.h>
#endif

#ifndef HAVE_IB_QP_CREATE_IWARP_WITHOUT_CM
#define IB_QP_CREATE_IWARP_WITHOUT_CM (1 << 27)
#endif

#ifndef HAVE_IWARP_OUTBOUND_QP_CREATE_FOR_SMC
struct iw_ext_conn_param {
	struct {
		union {
			__be32 daddr_v4;
#if IS_ENABLED(CONFIG_IPV6)
			struct in6_addr daddr_v6;
#endif
		};
		union {
			__be32 saddr_v4;
#if IS_ENABLED(CONFIG_IPV6)
			struct in6_addr saddr_v6;
#endif
		};
		__be16 dport;
		__u16 sport;
		unsigned short family;
	} sk_addr;
};
#endif

#ifndef HAVE_IB_DEVICE_GET_BY_NAME
struct ib_device *ib_device_get_by_name(const char *name,
					unsigned int driver_id);

void ib_device_put(struct ib_device *device);

#endif

#ifndef HAVE_KREF_READ
static inline int kref_read(const struct kref *kref)
{
	return atomic_read(&kref->refcount);
}
#endif

#ifndef HAVE_XARRAY
static inline int idr_alloc_cyclic_safe(struct idr *idr, int *id, void *ptr,
					spinlock_t *lock, int *next, int max)
{
	bool tried_twice = false;
	unsigned long flags;
	int idx;

idr_alloc:
	spin_lock_irqsave(lock, flags);
	idx = idr_alloc(idr, ptr, *next, max, GFP_NOWAIT);
	spin_unlock_irqrestore(lock, flags);

	if (idx >= 0) {
		*id = idx;
		*next = idx + 1;
	} else {
		if (!tried_twice && *next != 1) {
			*next = 1;
			tried_twice = true;
			goto idr_alloc;
		}
	}

	return idx >= 0 ? 0 : idx;
}

static inline void idr_remove_safe(struct idr *idr, int id, spinlock_t *lock)
{
	unsigned long flags;

	spin_lock_irqsave(lock, flags);
	idr_remove(idr, id);
	spin_unlock_irqrestore(lock, flags);
}
#endif

#ifndef HAVE_IB_UMEM_FIND_SINGLE_PG_SIZE
static inline unsigned long ib_umem_find_best_pgsz(struct ib_umem *umem,
						   unsigned long pgsz_bitmap,
						   unsigned long virt)
{
	return PAGE_SIZE;
}
#endif

#ifndef HAVE_IB_UMEM_NUM_DMA_BLOCKS
#include <rdma/ib_umem.h>
static inline size_t ib_umem_num_dma_blocks(struct ib_umem *umem,
					    unsigned long pgsz)
{
	return (size_t)((ALIGN(umem->address + umem->length, pgsz) -
			 ALIGN_DOWN(umem->address, pgsz))) /
	       pgsz;
}
#endif

#endif
