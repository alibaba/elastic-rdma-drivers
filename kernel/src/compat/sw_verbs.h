/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
 * Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.
 */

#ifndef SW_VERBS_H
#define SW_VERBS_H

#include <linux/interrupt.h>
#include <linux/workqueue.h>
#include "rdma_user_sw.h"
#include "sw_pool.h"
#include "sw_task.h"
#include "sw_hw_counters.h"
/* lack */
#include "sw_param.h"
#include "../kcompat.h"

static inline int pkey_match(u16 key1, u16 key2)
{
	return (((key1 & 0x7fff) != 0) &&
		((key1 & 0x7fff) == (key2 & 0x7fff)) &&
		((key1 & 0x8000) || (key2 & 0x8000))) ? 1 : 0;
}

/* Return >0 if psn_a > psn_b
 *	   0 if psn_a == psn_b
 *	  <0 if psn_a < psn_b
 */
static inline int psn_compare(u32 psn_a, u32 psn_b)
{
	s32 diff;

	diff = (psn_a - psn_b) << 8;
	return diff;
}

struct sw_ucontext {
	struct ib_ucontext ibuc;
	struct sw_pool_entry	pelem;
};

struct sw_pd {
	struct ib_pd            ibpd;
	struct sw_pool_entry	pelem;
	struct ib_mr		*internal_mr;
};

struct sw_ah {
	struct ib_ah		ibah;
	struct sw_pool_entry	pelem;
	struct sw_pd		*pd;
	struct sw_av		av;
};

struct sw_cqe {
	union {
		struct ib_wc		ibwc;
		struct ib_uverbs_wc	uibwc;
	};
};

struct sw_cq {
	struct ib_cq		ibcq;
	struct sw_pool_entry	pelem;
	struct sw_queue	*queue;
	spinlock_t		cq_lock;
	u8			notify;
	bool			is_dying;
	int			is_user;
	struct tasklet_struct	comp_task;
	struct erdma_cq		*master;
};

enum wqe_state {
	wqe_state_posted,
	wqe_state_processing,
	wqe_state_pending,
	wqe_state_done,
	wqe_state_error,
};

struct sw_sq {
	int			max_wr;
	int			max_sge;
	int			max_inline;
	spinlock_t		sq_lock; /* guard queue */
	struct sw_queue	*queue;
};

struct sw_rq {
	int			max_wr;
	int			max_sge;
	spinlock_t		producer_lock; /* guard queue producer */
	spinlock_t		consumer_lock; /* guard queue consumer */
	struct sw_queue	*queue;
};

struct sw_srq {
	struct ib_srq		ibsrq;
	struct sw_pool_entry	pelem;
	struct sw_pd		*pd;
	struct sw_rq		rq;
	u32			srq_num;

	int			limit;
	int			error;
};

enum sw_qp_state {
	QP_STATE_RESET,
	QP_STATE_INIT,
	QP_STATE_READY,
	QP_STATE_DRAIN,		/* req only */
	QP_STATE_DRAINED,	/* req only */
	QP_STATE_ERROR
};

struct sw_req_info {
	enum sw_qp_state	state;
	int			wqe_index;
	u32			psn;
	int			opcode;
	atomic_t		rd_atomic;
	int			wait_fence;
	int			need_rd_atomic;
	int			wait_psn;
	int			need_retry;
	int			noack_pkts;
	struct sw_task		task;
};

struct sw_comp_info {
	u32			psn;
	int			opcode;
	int			timeout;
	int			timeout_retry;
	int			started_retry;
	u32			retry_cnt;
	u32			rnr_retry;
	struct sw_task		task;
};

enum rdatm_res_state {
	rdatm_res_state_next,
	rdatm_res_state_new,
	rdatm_res_state_replay,
};

struct resp_res {
	int			type;
	int			replay;
	u32			first_psn;
	u32			last_psn;
	u32			cur_psn;
	enum rdatm_res_state	state;

	union {
		struct {
			struct sk_buff	*skb;
		} atomic;
		struct {
			struct sw_mem	*mr;
			u64		va_org;
			u32		rkey;
			u32		length;
			u64		va;
			u32		resid;
		} read;
	};
};

struct sw_resp_info {
	enum sw_qp_state	state;
	u32			msn;
	u32			psn;
	u32			ack_psn;
	int			opcode;
	int			drop_msg;
	int			goto_error;
	int			sent_psn_nak;
	enum ib_wc_status	status;
	u8			aeth_syndrome;

	/* Receive only */
	struct sw_recv_wqe	*wqe;

	/* RDMA read / atomic only */
	u64			va;
	struct sw_mem		*mr;
	u32			resid;
	u32			rkey;
	u32			length;
	u64			atomic_orig;

	/* SRQ only */
	struct {
		struct sw_recv_wqe	wqe;
		struct ib_sge		sge[SW_MAX_SGE];
	} srq_wqe;

	/* Responder resources. It's a circular list where the oldest
	 * resource is dropped first.
	 */
	struct resp_res		*resources;
	unsigned int		res_head;
	unsigned int		res_tail;
	struct resp_res		*res;
	struct sw_task		task;
};

struct sw_qp {
	struct sw_pool_entry	pelem;
	struct ib_qp		ibqp;
	struct ib_qp_attr	attr;
	unsigned int		valid;
	unsigned int		mtu;
	int			is_user;

	struct erdma_qp		*master;
	struct sw_pd		*pd;
	struct sw_srq		*srq;
	struct sw_cq		*scq;
	struct sw_cq		*rcq;

	enum ib_sig_type	sq_sig_type;

	struct sw_sq		sq;
	struct sw_rq		rq;

	struct socket		*sk;
	u32			dst_cookie;
	u16			src_port;

	struct sw_av		pri_av;
	struct sw_av		alt_av;

	/* list of mcast groups qp has joined (for cleanup) */
	struct list_head	grp_list;
	spinlock_t		grp_lock; /* guard grp_list */

	struct sk_buff_head	req_pkts;
	struct sk_buff_head	resp_pkts;
	struct sk_buff_head	send_pkts;

	struct sw_req_info	req;
	struct sw_comp_info	comp;
	struct sw_resp_info	resp;

	atomic_t		ssn;
	atomic_t		skb_out;
	int			need_req_skb;

	/* Timer for retranmitting packet when ACKs have been lost. RC
	 * only. The requester sets it when it is not already
	 * started. The responder resets it whenever an ack is
	 * received.
	 */
	struct timer_list retrans_timer;
	u64 qp_timeout_jiffies;

	/* Timer for handling RNR NAKS. */
	struct timer_list rnr_nak_timer;

	spinlock_t		state_lock; /* guard requester and completer */

	struct execute_work	cleanup_work;
};

enum sw_mem_state {
	SW_MEM_STATE_ZOMBIE,
	SW_MEM_STATE_INVALID,
	SW_MEM_STATE_FREE,
	SW_MEM_STATE_VALID,
};

enum sw_mem_type {
	SW_MEM_TYPE_NONE,
	SW_MEM_TYPE_DMA,
	SW_MEM_TYPE_MR,
	SW_MEM_TYPE_FMR,
	SW_MEM_TYPE_MW,
};

#define SW_BUF_PER_MAP		(PAGE_SIZE / sizeof(struct sw_phys_buf))

struct sw_phys_buf {
	u64      addr;
	u64      size;
};

struct sw_map {
	struct sw_phys_buf	buf[SW_BUF_PER_MAP];
};

struct sw_mem {
	struct sw_pool_entry	pelem;
	union {
		struct ib_mr		ibmr;
		struct ib_mw		ibmw;
	};

	struct ib_umem		*umem;

	enum sw_mem_state	state;
	enum sw_mem_type	type;
	u64			va;
	u64			iova;
	size_t			length;
	u32			offset;
	int			access;

	int			page_shift;
	int			page_mask;
	int			map_shift;
	int			map_mask;

	u32			num_buf;
	u32			nbuf;

	u32			max_buf;
	u32			num_map;

	struct sw_map		**map;
};

struct sw_mc_grp {
	struct sw_pool_entry	pelem;
	spinlock_t		mcg_lock; /* guard group */
	struct sw_dev		*sw;
	struct list_head	qp_list;
	union ib_gid		mgid;
	int			num_qp;
	u32			qkey;
	u16			pkey;
};

struct sw_mc_elem {
	struct sw_pool_entry	pelem;
	struct list_head	qp_list;
	struct list_head	grp_list;
	struct sw_qp		*qp;
	struct sw_mc_grp	*grp;
};

struct sw_port {
	struct ib_port_attr	attr;
	__be64			port_guid;
	__be64			subnet_prefix;
	spinlock_t		port_lock; /* guard port */
	unsigned int		mtu_cap;
	/* special QPs */
	u32			qp_smi_index;
	u32			qp_gsi_index;
};

struct sw_dev {
	struct ib_device	ib_dev;
	struct ib_device_attr	attr;
	int			max_ucontext;
	int			max_inline_data;
	struct mutex	usdev_lock;

	struct net_device	*ndev;
	struct erdma_dev	*master;

	int			xmit_errors;

	struct sw_pool		uc_pool;
	struct sw_pool		pd_pool;
	struct sw_pool		ah_pool;
	struct sw_pool		srq_pool;
	struct sw_pool		qp_pool;
	struct sw_pool		cq_pool;
	struct sw_pool		mr_pool;
	struct sw_pool		mw_pool;
	struct sw_pool		mc_grp_pool;
	struct sw_pool		mc_elem_pool;

	spinlock_t		pending_lock; /* guard pending_mmaps */
	struct list_head	pending_mmaps;

	spinlock_t		mmap_offset_lock; /* guard mmap_offset */
	u64			mmap_offset;

	atomic64_t		stats_counters[SW_NUM_OF_COUNTERS];

	struct sw_port		port;
	struct crypto_shash	*tfm;
};

static inline void sw_counter_inc(struct sw_dev *sw, enum sw_counters index)
{
	atomic64_inc(&sw->stats_counters[index]);
}

static inline struct sw_dev *to_rdev(struct ib_device *dev)
{
	return dev ? container_of(dev, struct sw_dev, ib_dev) : NULL;
}

static inline struct sw_ucontext *to_ruc(struct ib_ucontext *uc)
{
	return uc ? container_of(uc, struct sw_ucontext, ibuc) : NULL;
}

static inline struct sw_pd *to_rpd(struct ib_pd *pd)
{
	return pd ? container_of(pd, struct sw_pd, ibpd) : NULL;
}

static inline struct sw_ah *to_rah(struct ib_ah *ah)
{
	return ah ? container_of(ah, struct sw_ah, ibah) : NULL;
}

static inline struct sw_srq *to_rsrq(struct ib_srq *srq)
{
	return srq ? container_of(srq, struct sw_srq, ibsrq) : NULL;
}

static inline struct sw_qp *to_rqp(struct ib_qp *qp)
{
	return qp ? container_of(qp, struct sw_qp, ibqp) : NULL;
}

static inline struct sw_cq *to_rcq(struct ib_cq *cq)
{
	return cq ? container_of(cq, struct sw_cq, ibcq) : NULL;
}

static inline struct sw_mem *to_rmr(struct ib_mr *mr)
{
	return mr ? container_of(mr, struct sw_mem, ibmr) : NULL;
}

static inline struct sw_mem *to_rmw(struct ib_mw *mw)
{
	return mw ? container_of(mw, struct sw_mem, ibmw) : NULL;
}

static inline struct sw_pd *mr_pd(struct sw_mem *mr)
{
	return to_rpd(mr->ibmr.pd);
}

static inline u32 mr_lkey(struct sw_mem *mr)
{
	return mr->ibmr.lkey;
}

static inline u32 mr_rkey(struct sw_mem *mr)
{
	return mr->ibmr.rkey;
}

int sw_register_device(struct sw_dev *sw, const char *ibdev_name);

void sw_mc_cleanup(struct sw_pool_entry *arg);
/* verbs interface */
int sw_create_cq(struct ib_cq *ibcq, const struct ib_cq_init_attr *attr,
			 struct ib_udata *udata);
int sw_destroy_cq(struct ib_cq *ibcq, struct ib_udata *udata);
int sw_alloc_pd(struct ib_pd *ibpd, struct ib_udata *udata);
int sw_dealloc_pd(struct ib_pd *ibpd, struct ib_udata *udata);
void sw_init_ports(struct sw_dev *sw);
int sw_init(struct sw_dev *sw);
void sw_dealloc(struct sw_dev *sw);
void sw_set_mtu(struct sw_dev *sw, unsigned int ndev_mtu);
#ifdef HAVE_POST_CONST_WR
int sw_post_send(struct ib_qp *ibqp, const struct ib_send_wr *wr,
		 const struct ib_send_wr **bad_wr);
#else
int sw_post_send(struct ib_qp *ibqp, struct ib_send_wr *wr,
		 struct ib_send_wr **bad_wr);
#endif
#ifdef HAVE_POST_CONST_WR
int sw_post_recv(struct ib_qp *ibqp, const struct ib_recv_wr *wr,
		 const struct ib_recv_wr **bad_wr);
#else
int sw_post_recv(struct ib_qp *ibqp, struct ib_recv_wr *wr,
		 struct ib_recv_wr **bad_wr);
#endif
int sw_modify_qp(struct ib_qp *ibqp, struct ib_qp_attr *attr,
			 int mask, struct ib_udata *udata);
int sw_create_ah(struct ib_ah *ibah,
			 struct rdma_ah_attr *attr,
			 struct ib_udata *udata);
int sw_poll_cq(struct ib_cq *ibcq, int num_entries, struct ib_wc *wc);
int sw_req_notify_cq(struct ib_cq *ibcq, enum ib_cq_notify_flags flags);
struct ib_mr *sw_get_dma_mr(struct ib_pd *ibpd, int access);
#endif /* SW_VERBS_H */
