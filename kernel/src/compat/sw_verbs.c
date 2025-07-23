// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
 * Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.
 */

#include <linux/dma-mapping.h>
#include <net/addrconf.h>
#include <rdma/uverbs_ioctl.h>
#include "sw.h"
#include "sw_loc.h"
#include "sw_queue.h"
#include "sw_hw_counters.h"
#include "../erdma_verbs.h"

int sw_alloc_pd(struct ib_pd *ibpd, struct ib_udata *udata)
{
	struct sw_dev *sw = to_rdev(ibpd->device);
	struct sw_pd *pd = to_rpd(ibpd);

	return sw_add_to_pool(&sw->pd_pool, &pd->pelem);
}

int sw_dealloc_pd(struct ib_pd *ibpd, struct ib_udata *udata)
{
	struct sw_pd *pd = to_rpd(ibpd);

	sw_drop_ref(pd);
	return 0;
}

int sw_create_ah(struct ib_ah *ibah,
		 struct rdma_ah_attr *attr,
		 struct ib_udata *udata)

{
	int err;
	struct erdma_dev *dev = to_edev(ibah->device);
	struct sw_dev *sw = &dev->sw_dev;
	struct sw_ah *ah = to_rah(ibah);

	err = sw_av_chk_attr(sw, attr);
	if (err)
		return err;

	err = sw_add_to_pool(&sw->ah_pool, &ah->pelem);
	if (err)
		return err;

	sw_init_av(attr, &ah->av);
	return 0;
}

static int post_one_recv(struct sw_rq *rq, const struct ib_recv_wr *ibwr)
{
	int err;
	int i;
	u32 length;
	struct sw_recv_wqe *recv_wqe;
	int num_sge = ibwr->num_sge;

	if (unlikely(queue_full(rq->queue))) {
		err = -ENOMEM;
		goto err1;
	}

	if (unlikely(num_sge > rq->max_sge)) {
		err = -EINVAL;
		goto err1;
	}

	length = 0;
	for (i = 0; i < num_sge; i++)
		length += ibwr->sg_list[i].length;

	recv_wqe = producer_addr(rq->queue);
	recv_wqe->wr_id = ibwr->wr_id;
	recv_wqe->num_sge = num_sge;

	memcpy(recv_wqe->dma.sge, ibwr->sg_list,
	       num_sge * sizeof(struct ib_sge));

	recv_wqe->dma.length		= length;
	recv_wqe->dma.resid		= length;
	recv_wqe->dma.num_sge		= num_sge;
	recv_wqe->dma.cur_sge		= 0;
	recv_wqe->dma.sge_offset	= 0;

	/* make sure all changes to the work queue are written before we
	 * update the producer pointer
	 */
	smp_wmb();

	advance_producer(rq->queue);
	return 0;

err1:
	return err;
}

int sw_modify_qp(struct ib_qp *ibqp, struct ib_qp_attr *attr,
			 int mask, struct ib_udata *udata)
{
	int err;
	struct sw_dev *sw = to_rdev(ibqp->device);
	struct sw_qp *qp = to_rqp(ibqp);

	err = sw_qp_chk_attr(sw, qp, attr, mask);
	if (err)
		goto err1;

	err = sw_qp_from_attr(qp, attr, mask, udata);
	if (err)
		goto err1;

	return 0;

err1:
	return err;
}
#ifdef HAVE_POST_CONST_WR
static int validate_send_wr(struct sw_qp *qp, const struct ib_send_wr *ibwr,
#else
static int validate_send_wr(struct sw_qp *qp, struct ib_send_wr *ibwr,
#endif
			    unsigned int mask, unsigned int length)
{
	int num_sge = ibwr->num_sge;
	struct sw_sq *sq = &qp->sq;

	if (unlikely(num_sge > sq->max_sge))
		goto err1;

	if (unlikely(mask & WR_ATOMIC_MASK)) {
		if (length < 8)
			goto err1;

		if (atomic_wr(ibwr)->remote_addr & 0x7)
			goto err1;
	}

	if (unlikely((ibwr->send_flags & IB_SEND_INLINE) &&
		     (length > sq->max_inline)))
		goto err1;

	return 0;

err1:
	return -EINVAL;
}

static void init_send_wr(struct sw_qp *qp, struct sw_send_wr *wr,
#ifdef HAVE_POST_CONST_WR
			 const struct ib_send_wr *ibwr)
#else
			 struct ib_send_wr *ibwr)
#endif
{
	wr->wr_id = ibwr->wr_id;
	wr->num_sge = ibwr->num_sge;
	wr->opcode = ibwr->opcode;
	wr->send_flags = ibwr->send_flags;

	if (qp_type(qp) == IB_QPT_GSI) {
		wr->wr.ud.remote_qpn = ud_wr(ibwr)->remote_qpn;
		wr->wr.ud.remote_qkey = ud_wr(ibwr)->remote_qkey;
		wr->wr.ud.pkey_index = ud_wr(ibwr)->pkey_index;
		if (wr->opcode == IB_WR_SEND_WITH_IMM)
			wr->ex.imm_data = ibwr->ex.imm_data;
	}
}

#ifdef HAVE_POST_CONST_WR
static int init_send_wqe(struct sw_qp *qp, const struct ib_send_wr *ibwr,
#else
static int init_send_wqe(struct sw_qp *qp, struct ib_send_wr *ibwr,
#endif
			 unsigned int mask, unsigned int length,
			 struct sw_send_wqe *wqe)
{
	int num_sge = ibwr->num_sge;
	struct ib_sge *sge;
	int i;
	u8 *p;

	init_send_wr(qp, &wqe->wr, ibwr);

	if (qp_type(qp) == IB_QPT_UD ||
	    qp_type(qp) == IB_QPT_SMI ||
	    qp_type(qp) == IB_QPT_GSI)
		memcpy(&wqe->av, &to_rah(ud_wr(ibwr)->ah)->av, sizeof(wqe->av));

	if (unlikely(ibwr->send_flags & IB_SEND_INLINE)) {
		p = wqe->dma.inline_data;

		sge = ibwr->sg_list;
		for (i = 0; i < num_sge; i++, sge++) {
			memcpy(p, (void *)(uintptr_t)sge->addr,
					sge->length);

			p += sge->length;
		}
	} else if (mask & WR_REG_MASK) {
		wqe->mask = mask;
		wqe->state = wqe_state_posted;
		return 0;
	} else
		memcpy(wqe->dma.sge, ibwr->sg_list,
		       num_sge * sizeof(struct ib_sge));

	wqe->iova = mask & WR_ATOMIC_MASK ? atomic_wr(ibwr)->remote_addr :
		mask & WR_READ_OR_WRITE_MASK ? rdma_wr(ibwr)->remote_addr : 0;
	wqe->mask		= mask;
	wqe->dma.length		= length;
	wqe->dma.resid		= length;
	wqe->dma.num_sge	= num_sge;
	wqe->dma.cur_sge	= 0;
	wqe->dma.sge_offset	= 0;
	wqe->state		= wqe_state_posted;
	wqe->ssn		= atomic_add_return(1, &qp->ssn);

	return 0;
}

#ifdef HAVE_POST_CONST_WR
static int post_one_send(struct sw_qp *qp, const struct ib_send_wr *ibwr,
#else
static int post_one_send(struct sw_qp *qp, struct ib_send_wr *ibwr,
#endif
			 unsigned int mask, u32 length)
{
	int err;
	struct sw_sq *sq = &qp->sq;
	struct sw_send_wqe *send_wqe;
	unsigned long flags;

	err = validate_send_wr(qp, ibwr, mask, length);
	if (err)
		return err;

	spin_lock_irqsave(&qp->sq.sq_lock, flags);

	if (unlikely(queue_full(sq->queue))) {
		err = -ENOMEM;
		goto err1;
	}

	send_wqe = producer_addr(sq->queue);

	err = init_send_wqe(qp, ibwr, mask, length, send_wqe);
	if (unlikely(err))
		goto err1;

	/*
	 * make sure all changes to the work queue are
	 * written before we update the producer pointer
	 */
	smp_wmb();

	advance_producer(sq->queue);
	spin_unlock_irqrestore(&qp->sq.sq_lock, flags);

	return 0;

err1:
	spin_unlock_irqrestore(&qp->sq.sq_lock, flags);
	return err;
}

#ifdef HAVE_POST_CONST_WR
static int sw_post_send_kernel(struct sw_qp *qp, const struct ib_send_wr *wr,
			       const struct ib_send_wr **bad_wr)
#else
static int sw_post_send_kernel(struct sw_qp *qp, struct ib_send_wr *wr,
			       struct ib_send_wr **bad_wr)
#endif
{
	unsigned int length = 0, mask;
	int err = 0, i;
	struct ib_send_wr *next;

	while (wr) {
		mask = wr_opcode_mask(wr->opcode, qp);
		if (unlikely(!mask)) {
			err = -EINVAL;
			*bad_wr = wr;
			break;
		}

		if (unlikely((wr->send_flags & IB_SEND_INLINE) &&
			     !(mask & WR_INLINE_MASK))) {
			err = -EINVAL;
			*bad_wr = wr;
			break;
		}

		next = wr->next;

		length = 0;
		for (i = 0; i < wr->num_sge; i++)
			length += wr->sg_list[i].length;

		err = post_one_send(qp, wr, mask, length);
		if (err) {
			*bad_wr = wr;
			break;
		}
		wr = next;
	}

	sw_run_task(&qp->req.task, 1);
	if (unlikely(qp->req.state == QP_STATE_ERROR))
		sw_run_task(&qp->comp.task, 1);

	return err;
}

#ifdef HAVE_POST_CONST_WR
int sw_post_send(struct ib_qp *ibqp, const struct ib_send_wr *wr,
		 const struct ib_send_wr **bad_wr)
#else
int sw_post_send(struct ib_qp *ibqp, struct ib_send_wr *wr,
		 struct ib_send_wr **bad_wr)
#endif
{
	struct sw_qp *qp = to_rqp(ibqp);

	if (unlikely(!qp->valid)) {
		*bad_wr = wr;
		return -EINVAL;
	}

	if (unlikely(qp->req.state < QP_STATE_READY)) {
		*bad_wr = wr;
		return -EINVAL;
	}

	return sw_post_send_kernel(qp, wr, bad_wr);
}

#ifdef HAVE_POST_CONST_WR
int sw_post_recv(struct ib_qp *ibqp, const struct ib_recv_wr *wr,
		 const struct ib_recv_wr **bad_wr)
#else
int sw_post_recv(struct ib_qp *ibqp, struct ib_recv_wr *wr,
		 struct ib_recv_wr **bad_wr)
#endif
{
	int err = 0;
	struct sw_qp *qp = to_rqp(ibqp);
	struct sw_rq *rq = &qp->rq;
	unsigned long flags;

	if (unlikely((qp_state(qp) < IB_QPS_INIT) || !qp->valid)) {
		*bad_wr = wr;
		err = -EINVAL;
		goto err1;
	}

	if (unlikely(qp->srq)) {
		*bad_wr = wr;
		err = -EINVAL;
		goto err1;
	}

	spin_lock_irqsave(&rq->producer_lock, flags);

	while (wr) {
		err = post_one_recv(rq, wr);
		if (unlikely(err)) {
			*bad_wr = wr;
			break;
		}
		wr = wr->next;
	}

	spin_unlock_irqrestore(&rq->producer_lock, flags);

	if (qp->resp.state == QP_STATE_ERROR)
		sw_run_task(&qp->resp.task, 1);

err1:
	return err;
}

int sw_create_cq(struct ib_cq *ibcq, const struct ib_cq_init_attr *attr,
			 struct ib_udata *udata)
{
	int err;
	struct ib_device *dev = ibcq->device;
	struct sw_dev *sw = to_rdev(dev);
	struct sw_cq *cq = to_rcq(ibcq);
	struct sw_create_cq_resp __user *uresp = NULL;

	if (udata)
		return -EINVAL;

	if (attr->flags)
		return -EINVAL;

	err = sw_cq_chk_attr(sw, NULL, attr->cqe, attr->comp_vector);
	if (err)
		return err;

	err = sw_cq_from_init(sw, cq, attr->cqe, attr->comp_vector, udata,
			       uresp);
	if (err)
		return err;

	return sw_add_to_pool(&sw->cq_pool, &cq->pelem);
}

int sw_destroy_cq(struct ib_cq *ibcq, struct ib_udata *udata)
{
	struct sw_cq *cq = to_rcq(ibcq);

	sw_cq_disable(cq);

	sw_drop_ref(cq);
	return 0;
}

int sw_poll_cq(struct ib_cq *ibcq, int num_entries, struct ib_wc *wc)
{
	int i;
	struct sw_cq *cq = to_rcq(ibcq);
	struct sw_cqe *cqe;
	unsigned long flags;

	spin_lock_irqsave(&cq->cq_lock, flags);
	for (i = 0; i < num_entries; i++) {
		cqe = queue_head(cq->queue);
		if (!cqe)
			break;

		memcpy(wc++, &cqe->ibwc, sizeof(*wc));
		advance_consumer(cq->queue);
	}
	spin_unlock_irqrestore(&cq->cq_lock, flags);

	return i;
}

int sw_req_notify_cq(struct ib_cq *ibcq, enum ib_cq_notify_flags flags)
{
	struct sw_cq *cq = to_rcq(ibcq);
	unsigned long irq_flags;
	int ret = 0;

	spin_lock_irqsave(&cq->cq_lock, irq_flags);
	if (cq->notify != IB_CQ_NEXT_COMP)
		cq->notify = flags & IB_CQ_SOLICITED_MASK;

	if ((flags & IB_CQ_REPORT_MISSED_EVENTS) && !queue_empty(cq->queue))
		ret = 1;

	spin_unlock_irqrestore(&cq->cq_lock, irq_flags);

	return ret;
}

struct ib_mr *sw_get_dma_mr(struct ib_pd *ibpd, int access)
{
	struct sw_dev *sw = to_rdev(ibpd->device);
	struct sw_pd *pd = to_rpd(ibpd);
	struct sw_mem *mr;

	mr = sw_alloc(&sw->mr_pool);
	if (!mr)
		return ERR_PTR(-ENOMEM);

	sw_add_index(mr);
	sw_add_ref(pd);
	sw_mem_init_dma(pd, access, mr);

	return &mr->ibmr;
}
