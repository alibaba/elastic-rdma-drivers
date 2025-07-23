// SPDX-License-Identifier: GPL-2.0

/* Authors: Cheng Xu <chengyou@linux.alibaba.com> */
/*          Kai Shen <kaishen@linux.alibaba.com> */
/* Copyright (c) 2020-2022, Alibaba Group. */

#ifndef __ERDMA_SW_H__
#define __ERDMA_SW_H__

#include "kcompat.h"
#include "erdma_verbs.h"

int erdma_compat_init(void);
void erdma_compat_exit(void);

void erdma_gen_port_from_qpn(u32 sip, u32 dip, u32 lqpn, u32 rqpn, u16 *sport,
			     u16 *dport);

int erdma_handle_compat_attr(struct erdma_qp *qp, struct ib_qp_attr *attr,
			     int attr_mask);

#ifdef HAVE_OLD_GID_OPERATION
int erdma_add_gid(const struct ib_gid_attr *attr, void **context);

int erdma_del_gid(const struct ib_gid_attr *attr, void **context);
#else
int erdma_add_gid(struct ib_device *device, u8 port_num, unsigned int index,
		  const union ib_gid *gid, const struct ib_gid_attr *attr,
		  void **context);

int erdma_del_gid(struct ib_device *device, u8 port_num, unsigned int index,
		  void **context);
#endif

int erdma_create_ah(struct ib_ah *ibah,
#ifdef HAVE_CREATE_AH_RDMA_INIT_ATTR
		    struct rdma_ah_init_attr *init_attr,
#else
		    struct rdma_ah_attr *ah_attr, u32 flags,
#endif
		    struct ib_udata *udata);

#ifndef HAVE_AH_CORE_ALLOCATION
#ifdef HAVE_CREATE_AH_FLAGS
struct ib_ah *erdma_kzalloc_ah(struct ib_pd *ibpd, struct rdma_ah_attr *ah_attr,
			       u32 flags, struct ib_udata *udata);
#elif defined(HAVE_CREATE_AH_RDMA_ATTR)
struct ib_ah *erdma_kzalloc_ah(struct ib_pd *ibpd, struct rdma_ah_attr *ah_attr,
			       struct ib_udata *udata);
#else
struct ib_ah *erdma_kzalloc_ah(struct ib_pd *ibpd, struct ib_ah_attr *ah_attr);
#endif
#endif

#ifdef HAVE_AH_CORE_ALLOCATION_DESTROY_RC
int erdma_destroy_ah(struct ib_ah *ibah, u32 flags);
#elif defined(HAVE_AH_CORE_ALLOCATION) && defined (HAVE_DESTROY_AH_VOID)
void erdma_destroy_ah(struct ib_ah *ibah, u32 flags);
#elif defined(HAVE_DESTROY_AH_FLAGS)
int erdma_destroy_ah(struct ib_ah *ibah, u32 flags);
#else
int erdma_destroy_ah(struct ib_ah *ibah);
#endif

#ifdef HAVE_ERDMA_MAD
#include "compat/sw_verbs.h"
#include "compat/sw_net.h"

int erdma_modify_mad_qp(struct ib_qp *ibqp, struct ib_qp_attr *attr,
			int attr_mask, struct ib_udata *udata);

int erdma_create_mad_qp(struct ib_qp *ibqp, struct ib_qp_init_attr *attrs,
			struct ib_udata *udata);
#ifdef HAVE_POST_CONST_WR
int erdma_post_send_mad(struct ib_qp *ibqp, const struct ib_send_wr *send_wr,
			const struct ib_send_wr **bad_send_wr);
#else
int erdma_post_send_mad(struct ib_qp *qp, struct ib_send_wr *send_wr,
			struct ib_send_wr **bad_send_wr);
#endif
#ifdef HAVE_POST_CONST_WR
int erdma_post_recv_mad(struct ib_qp *ibqp, const struct ib_recv_wr *recv_wr,
			const struct ib_recv_wr **bad_recv_wr);
#else
int erdma_post_recv_mad(struct ib_qp *ibqp, struct ib_recv_wr *recv_wr,
			struct ib_recv_wr **bad_recv_wr);
#endif

int erdma_create_qp_mad(struct ib_qp *ibqp, struct ib_qp_init_attr *attrs,
			struct ib_udata *udata);
int attach_sw_dev(struct erdma_dev *dev);
void detach_sw_dev(struct erdma_dev *dev);
int erdma_mad_poll_cq(struct ib_cq *ibcq, int num_entries, struct ib_wc *wc);
int erdma_mad_req_notify_cq(struct ib_cq *ibcq, enum ib_cq_notify_flags flags);
void erdma_destroy_mad_qp(struct ib_qp *ibqp);
void detach_sw_pd(struct erdma_pd *pd);
void detach_sw_cq(struct erdma_cq *cq);
#endif
#endif
