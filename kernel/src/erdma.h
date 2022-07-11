/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */

/* Authors: Cheng Xu <chengyou@linux.alibaba.com> */
/*          Kai Shen <kaishen@linux.alibaba.com> */
/* Copyright (c) 2020-2022, Alibaba Group. */

#ifndef __ERDMA_H__
#define __ERDMA_H__

#include "kcompat.h"
#include <linux/bitfield.h>
#include <linux/netdevice.h>
#include <linux/pci.h>
#ifdef HAVE_XARRAY
#include <linux/xarray.h>
#endif
#include <rdma/ib_verbs.h>

#include "erdma_debug.h"
#include "erdma_hw.h"
#include "erdma_ioctl.h"
#include "erdma_stats.h"

#define ERDMA_MAJOR_VER 0
#define ERDMA_MEDIUM_VER 2
#define ERDMA_MINOR_VER 18

#define DRV_MODULE_NAME "erdma"
#define ERDMA_NODE_DESC "Elastic RDMA(iWARP) stack"

struct erdma_stats {
	atomic64_t value[ERDMA_STATS_MAX];
};

struct erdma_eq {
	void *qbuf;
	dma_addr_t qbuf_dma_addr;

	spinlock_t lock;

	u32 depth;

	u16 ci;
	u16 rsvd;

	atomic64_t event_num;
	atomic64_t notify_num;

	u64 __iomem *db_addr;
	u64 *db_record;
};

struct erdma_cmdq_sq {
	void *qbuf;
	dma_addr_t qbuf_dma_addr;

	spinlock_t lock;

	u32 depth;
	u16 ci;
	u16 pi;

	u16 wqebb_cnt;

	u64 total_cmds;
	u64 total_comp_cmds;
	u64 *db_record;
};

struct erdma_cmdq_cq {
	void *qbuf;
	dma_addr_t qbuf_dma_addr;

	spinlock_t lock;

	u32 depth;
	u32 ci;
	u32 cmdsn;

	u64 *db_record;

	atomic64_t armed_num;
};

enum {
	ERDMA_CMD_STATUS_INIT,
	ERDMA_CMD_STATUS_ISSUED,
	ERDMA_CMD_STATUS_FINISHED,
	ERDMA_CMD_STATUS_TIMEOUT
};

struct erdma_comp_wait {
	struct completion wait_event;
	u32 cmd_status;
	u32 ctx_id;
	u16 sq_pi;
	u8 comp_status;
	u8 rsvd;
	u32 comp_data[4];
};

enum {
	ERDMA_CMDQ_STATE_OK_BIT = 0,
	ERDMA_CMDQ_STATE_TIMEOUT_BIT = 1,
	ERDMA_CMDQ_STATE_CTX_ERR_BIT = 2,
};

#define ERDMA_CMDQ_TIMEOUT_MS 15000
#define ERDMA_REG_ACCESS_WAIT_MS 20
#define ERDMA_WAIT_DEV_DONE_CNT 500

struct erdma_cmdq {
	unsigned long *comp_wait_bitmap;
	struct erdma_comp_wait *wait_pool;
	spinlock_t lock;

	bool use_event;

	struct erdma_cmdq_sq sq;
	struct erdma_cmdq_cq cq;
	struct erdma_eq eq;

	unsigned long state;

	struct semaphore credits;
	u16 max_outstandings;
};

#define COMPROMISE_CC ERDMA_CC_CUBIC
enum erdma_cc_alg {
	ERDMA_CC_NEWRENO = 0,
	ERDMA_CC_CUBIC,
	ERDMA_CC_HPCC_RTT,
	ERDMA_CC_HPCC_ECN,
	ERDMA_CC_HPCC_INT,
	ERDMA_CC_METHODS_NUM
};

struct erdma_devattr {
	u32 fw_version;

	unsigned char peer_addr[ETH_ALEN];

	int numa_node;
	enum erdma_cc_alg cc;
	u32 grp_num;
	int irq_num;

	bool disable_dwqe;
	u16 dwqe_pages;
	u16 dwqe_entries;

	u32 max_qp;
	u32 max_send_wr;
	u32 max_recv_wr;
	u32 max_ord;
	u32 max_ird;

	u32 max_send_sge;
	u32 max_recv_sge;
	u32 max_sge_rd;
	u32 max_cq;
	u32 max_cqe;
	u64 max_mr_size;
	u32 max_mr;
	u32 max_pd;
	u32 max_mw;
	u32 local_dma_key;
};

#define ERDMA_IRQNAME_SIZE 50

struct erdma_irq {
	char name[ERDMA_IRQNAME_SIZE];
	u32 msix_vector;
	cpumask_t affinity_hint_mask;
};

struct erdma_eq_cb {
	bool ready;
	void *dev; /* All EQs use this fields to get erdma_dev struct */
	struct erdma_irq irq;
	struct erdma_eq eq;
	struct tasklet_struct tasklet;
};

struct erdma_resource_cb {
	unsigned long *bitmap;
	spinlock_t lock;
	u32 next_alloc_idx;
	u32 max_cap;
};

enum {
	ERDMA_RES_TYPE_PD = 0,
	ERDMA_RES_TYPE_STAG_IDX = 1,
	ERDMA_RES_CNT = 2,
};

#define ERDMA_EXTRA_BUFFER_SIZE ERDMA_DB_SIZE
#define WARPPED_BUFSIZE(size) ((size) + ERDMA_EXTRA_BUFFER_SIZE)

struct erdma_dev {
	struct ib_device ibdev;
	struct net_device *netdev;
	struct pci_dev *pdev;
	struct notifier_block netdev_nb;

	resource_size_t func_bar_addr;
	resource_size_t func_bar_len;
	u8 __iomem *func_bar;

	struct erdma_devattr attrs;
	/* physical port state (only one port per device) */
	enum ib_port_state state;

	/* cmdq and aeq use the same msix vector */
	struct erdma_irq comm_irq;
	struct erdma_cmdq cmdq;
	struct erdma_eq aeq;
	struct erdma_eq_cb ceqs[ERDMA_NUM_MSIX_VEC - 1];

	struct erdma_stats stats;
	spinlock_t lock;
	struct erdma_resource_cb res_cb[ERDMA_RES_CNT];
#ifdef HAVE_XARRAY
	struct xarray qp_xa;
	struct xarray cq_xa;
#else
	spinlock_t idr_lock;
	struct idr qp_idr;
	struct idr cq_idr;
#endif

	u32 next_alloc_qpn;
	u32 next_alloc_cqn;

	spinlock_t db_bitmap_lock;
	/* We provide max 64 uContexts that each has one SQ doorbell Page. */
	DECLARE_BITMAP(sdb_page, ERDMA_DWQE_TYPE0_CNT);
	/*
	 * We provide max 496 uContexts that each has one SQ normal Db,
	 * and one directWQE db。
	 */
	DECLARE_BITMAP(sdb_entry, ERDMA_DWQE_TYPE1_CNT);

	atomic_t num_ctx;
	atomic_t num_cep;
	struct list_head cep_list;
#ifndef HAVE_IB_DEVICE_GET_BY_NAME
	struct list_head dev_list;
#endif
};

static inline void *get_queue_entry(void *qbuf, u32 idx, u32 depth, u32 shift)
{
	idx &= (depth - 1);

	return qbuf + (idx << shift);
}

static inline struct erdma_dev *to_edev(struct ib_device *ibdev)
{
	return container_of(ibdev, struct erdma_dev, ibdev);
}

static inline u32 erdma_reg_read32(struct erdma_dev *dev, u32 reg)
{
	return readl(dev->func_bar + reg);
}

static inline u64 erdma_reg_read64(struct erdma_dev *dev, u32 reg)
{
	return readq(dev->func_bar + reg);
}

static inline void erdma_reg_write32(struct erdma_dev *dev, u32 reg, u32 value)
{
	writel(value, dev->func_bar + reg);
}

static inline void erdma_reg_write64(struct erdma_dev *dev, u32 reg, u64 value)
{
	writeq(value, dev->func_bar + reg);
}

static inline u32 erdma_reg_read32_filed(struct erdma_dev *dev, u32 reg,
					 u32 filed_mask)
{
	u32 val = erdma_reg_read32(dev, reg);

	return FIELD_GET(filed_mask, val);
}

int erdma_cmdq_init(struct erdma_dev *dev);
void erdma_finish_cmdq_init(struct erdma_dev *dev);
void erdma_cmdq_destroy(struct erdma_dev *dev);

void erdma_cmdq_build_reqhdr(u64 *hdr, u32 mod, u32 op);
int erdma_post_cmd_wait(struct erdma_cmdq *cmdq, u64 *req, u32 req_size,
			u64 *resp0, u64 *resp1);
void erdma_cmdq_completion_handler(struct erdma_cmdq *cmdq);

int erdma_ceqs_init(struct erdma_dev *dev);
void erdma_ceqs_uninit(struct erdma_dev *dev);
void notify_eq(struct erdma_eq *eq);
void *get_next_valid_eqe(struct erdma_eq *eq);

int erdma_aeq_init(struct erdma_dev *dev);
void erdma_aeq_destroy(struct erdma_dev *dev);

void erdma_aeq_event_handler(struct erdma_dev *dev);
void erdma_ceq_completion_handler(struct erdma_eq_cb *ceq_cb);

void erdma_chrdev_destroy(void);
int erdma_chrdev_init(void);

#ifndef HAVE_XARRAY
static inline int idr_alloc_cyclic_safe(struct idr *idr, int *id, void *ptr,
					spinlock_t *lock, int *next, int max)
{
	unsigned long flags;
	bool tried_twice = false;
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

#endif
