// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
 * Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.
 */

#include <linux/skbuff.h>
#include <crypto/hash.h>

#include "sw.h"
#include "sw_loc.h"
#include "sw_queue.h"

static int next_opcode(struct sw_qp *qp, struct sw_send_wqe *wqe,
		       u32 opcode);

static inline void retry_first_write_send(struct sw_qp *qp,
					  struct sw_send_wqe *wqe,
					  unsigned int mask, int npsn)
{
	int i;

	for (i = 0; i < npsn; i++) {
		int to_send = (wqe->dma.resid > qp->mtu) ?
				qp->mtu : wqe->dma.resid;

		qp->req.opcode = next_opcode(qp, wqe,
					     wqe->wr.opcode);

		if (wqe->wr.send_flags & IB_SEND_INLINE) {
			wqe->dma.resid -= to_send;
			wqe->dma.sge_offset += to_send;
		} else {
			advance_dma_data(&wqe->dma, to_send);
		}
		if (mask & WR_WRITE_MASK)
			wqe->iova += qp->mtu;
	}
}

static void req_retry(struct sw_qp *qp)
{
	struct sw_send_wqe *wqe;
	unsigned int wqe_index;
	unsigned int mask;
	int npsn;
	int first = 1;

	qp->req.wqe_index	= consumer_index(qp->sq.queue);
	qp->req.psn		= qp->comp.psn;
	qp->req.opcode		= -1;

	for (wqe_index = consumer_index(qp->sq.queue);
		wqe_index != producer_index(qp->sq.queue);
		wqe_index = next_index(qp->sq.queue, wqe_index)) {
		wqe = addr_from_index(qp->sq.queue, wqe_index);
		mask = wr_opcode_mask(wqe->wr.opcode, qp);

		if (wqe->state == wqe_state_posted)
			break;

		if (wqe->state == wqe_state_done)
			continue;

		wqe->iova = (mask & WR_ATOMIC_MASK) ?
			     wqe->wr.wr.atomic.remote_addr :
			     (mask & WR_READ_OR_WRITE_MASK) ?
			     wqe->wr.wr.rdma.remote_addr :
			     0;

		if (!first || (mask & WR_READ_MASK) == 0) {
			wqe->dma.resid = wqe->dma.length;
			wqe->dma.cur_sge = 0;
			wqe->dma.sge_offset = 0;
		}

		if (first) {
			first = 0;

			if (mask & WR_WRITE_OR_SEND_MASK) {
				npsn = (qp->comp.psn - wqe->first_psn) &
					BTH_PSN_MASK;
				retry_first_write_send(qp, wqe, mask, npsn);
			}

			if (mask & WR_READ_MASK) {
				npsn = (wqe->dma.length - wqe->dma.resid) /
					qp->mtu;
				wqe->iova += npsn * qp->mtu;
			}
		}

		wqe->state = wqe_state_posted;
	}
}

void rnr_nak_timer(struct timer_list *t)
{
	struct sw_qp *qp = from_timer(qp, t, rnr_nak_timer);

	pr_debug("qp#%d rnr nak timer fired\n", qp_num(qp));
	sw_run_task(&qp->req.task, 1);
}

static struct sw_send_wqe *req_next_wqe(struct sw_qp *qp)
{
	struct sw_send_wqe *wqe = queue_head(qp->sq.queue);
	unsigned long flags;

	if (unlikely(qp->req.state == QP_STATE_DRAIN)) {
		/* check to see if we are drained;
		 * state_lock used by requester and completer
		 */
		spin_lock_irqsave(&qp->state_lock, flags);
		do {
			if (qp->req.state != QP_STATE_DRAIN) {
				/* comp just finished */
				spin_unlock_irqrestore(&qp->state_lock,
						       flags);
				break;
			}

			if (wqe && ((qp->req.wqe_index !=
				consumer_index(qp->sq.queue)) ||
				(wqe->state != wqe_state_posted))) {
				/* comp not done yet */
				spin_unlock_irqrestore(&qp->state_lock,
						       flags);
				break;
			}

			qp->req.state = QP_STATE_DRAINED;
			spin_unlock_irqrestore(&qp->state_lock, flags);

			if (qp->ibqp.event_handler) {
				struct ib_event ev;

				ev.device = qp->ibqp.device;
				ev.element.qp = &qp->ibqp;
				ev.event = IB_EVENT_SQ_DRAINED;
				qp->ibqp.event_handler(&ev,
					qp->ibqp.qp_context);
			}
		} while (0);
	}

	if (qp->req.wqe_index == producer_index(qp->sq.queue))
		return NULL;

	wqe = addr_from_index(qp->sq.queue, qp->req.wqe_index);

	if (unlikely((qp->req.state == QP_STATE_DRAIN ||
		      qp->req.state == QP_STATE_DRAINED) &&
		     (wqe->state != wqe_state_processing)))
		return NULL;

	if (unlikely((wqe->wr.send_flags & IB_SEND_FENCE) &&
		     (qp->req.wqe_index != consumer_index(qp->sq.queue)))) {
		qp->req.wait_fence = 1;
		return NULL;
	}

	wqe->mask = wr_opcode_mask(wqe->wr.opcode, qp);
	return wqe;
}

static int next_opcode(struct sw_qp *qp, struct sw_send_wqe *wqe,
		       u32 opcode)
{
	switch (qp_type(qp)) {
	case IB_QPT_GSI:
		switch (opcode) {
		case IB_WR_SEND:
			return IB_OPCODE_UD_SEND_ONLY;

		case IB_WR_SEND_WITH_IMM:
			return IB_OPCODE_UD_SEND_ONLY_WITH_IMMEDIATE;
		}
		break;

	default:
		break;
	}

	return -EINVAL;
}

static inline int check_init_depth(struct sw_qp *qp, struct sw_send_wqe *wqe)
{
	int depth;

	if (wqe->has_rd_atomic)
		return 0;

	qp->req.need_rd_atomic = 1;
	depth = atomic_dec_return(&qp->req.rd_atomic);

	if (depth >= 0) {
		qp->req.need_rd_atomic = 0;
		wqe->has_rd_atomic = 1;
		return 0;
	}

	atomic_inc(&qp->req.rd_atomic);
	return -EAGAIN;
}

static inline int get_mtu(struct sw_qp *qp)
{
	struct sw_dev *sw = to_rdev(qp->ibqp.device);

	if ((qp_type(qp) == IB_QPT_RC) || (qp_type(qp) == IB_QPT_UC))
		return qp->mtu;

	return sw->port.mtu_cap;
}

static struct sk_buff *init_req_packet(struct sw_qp *qp,
				       struct sw_send_wqe *wqe,
				       int opcode, int payload,
				       struct sw_pkt_info *pkt)
{
	struct sw_dev		*sw = to_rdev(qp->ibqp.device);
	struct sk_buff		*skb;
	struct sw_send_wr	*ibwr = &wqe->wr;
	struct sw_av		*av;
	int			pad = (-payload) & 0x3;
	int			paylen;
	int			solicited;
	u16			pkey;
	u32			qp_num;
	int			ack_req;

	/* length from start of bth to end of icrc */
	paylen = sw_opcode[opcode].length + payload + pad + SW_ICRC_SIZE;

	/* pkt->hdr, sw, port_num and mask are initialized in ifc
	 * layer
	 */
	pkt->opcode	= opcode;
	pkt->qp		= qp;
	pkt->psn	= qp->req.psn;
	pkt->mask	= sw_opcode[opcode].mask;
	pkt->paylen	= paylen;
	pkt->offset	= 0;
	pkt->wqe	= wqe;

	/* init skb */
	av = sw_get_av(pkt);
	skb = sw_init_packet(sw, av, paylen, pkt);
	if (unlikely(!skb))
		return NULL;

	/* init bth */
	solicited = (ibwr->send_flags & IB_SEND_SOLICITED) &&
			(pkt->mask & SW_END_MASK) &&
			((pkt->mask & (SW_SEND_MASK)) ||
			(pkt->mask & (SW_WRITE_MASK | SW_IMMDT_MASK)) ==
			(SW_WRITE_MASK | SW_IMMDT_MASK));

	pkey = IB_DEFAULT_PKEY_FULL;

	qp_num = (pkt->mask & SW_DETH_MASK) ? ibwr->wr.ud.remote_qpn :
					 qp->attr.dest_qp_num;

	ack_req = ((pkt->mask & SW_END_MASK) ||
		(qp->req.noack_pkts++ > SW_MAX_PKT_PER_ACK));
	if (ack_req)
		qp->req.noack_pkts = 0;

	bth_init(pkt, pkt->opcode, solicited, 0, pad, pkey, qp_num,
		 ack_req, pkt->psn);

	/* init optional headers */
	if (pkt->mask & SW_RETH_MASK) {
		reth_set_rkey(pkt, ibwr->wr.rdma.rkey);
		reth_set_va(pkt, wqe->iova);
		reth_set_len(pkt, wqe->dma.resid);
	}

	if (pkt->mask & SW_IMMDT_MASK)
		immdt_set_imm(pkt, ibwr->ex.imm_data);

	if (pkt->mask & SW_IETH_MASK)
		ieth_set_rkey(pkt, ibwr->ex.invalidate_rkey);

	if (pkt->mask & SW_ATMETH_MASK) {
		atmeth_set_va(pkt, wqe->iova);
		if (opcode == IB_OPCODE_RC_COMPARE_SWAP ||
		    opcode == IB_OPCODE_RD_COMPARE_SWAP) {
			atmeth_set_swap_add(pkt, ibwr->wr.atomic.swap);
			atmeth_set_comp(pkt, ibwr->wr.atomic.compare_add);
		} else {
			atmeth_set_swap_add(pkt, ibwr->wr.atomic.compare_add);
		}
		atmeth_set_rkey(pkt, ibwr->wr.atomic.rkey);
	}

	if (pkt->mask & SW_DETH_MASK) {
		if (qp->ibqp.qp_num == 1)
			deth_set_qkey(pkt, GSI_QKEY);
		else
			deth_set_qkey(pkt, ibwr->wr.ud.remote_qkey);
		deth_set_sqp(pkt, qp->ibqp.qp_num);
	}

	return skb;
}

static int fill_packet(struct sw_qp *qp, struct sw_send_wqe *wqe,
		       struct sw_pkt_info *pkt, struct sk_buff *skb,
		       int paylen)
{
	struct sw_dev *sw = to_rdev(qp->ibqp.device);
	u32 crc = 0;
	u32 *p;
	int err;

	err = sw_prepare(pkt, skb, &crc);
	if (err)
		return err;

	if (pkt->mask & SW_WRITE_OR_SEND) {
		if (wqe->wr.send_flags & IB_SEND_INLINE) {
			u8 *tmp = &wqe->dma.inline_data[wqe->dma.sge_offset];

			crc = sw_crc32(sw, crc, tmp, paylen);
			memcpy(payload_addr(pkt), tmp, paylen);

			wqe->dma.resid -= paylen;
			wqe->dma.sge_offset += paylen;
		} else {
			err = copy_data(qp->pd, 0, &wqe->dma,
					payload_addr(pkt), paylen,
					from_mem_obj,
					&crc);
			if (err)
				return err;
		}
		if (bth_pad(pkt)) {
			u8 *pad = payload_addr(pkt) + paylen;

			memset(pad, 0, bth_pad(pkt));
			crc = sw_crc32(sw, crc, pad, bth_pad(pkt));
		}
	}
	p = payload_addr(pkt) + paylen + bth_pad(pkt);

	*p = ~crc;

	return 0;
}

static void update_wqe_state(struct sw_qp *qp,
		struct sw_send_wqe *wqe,
		struct sw_pkt_info *pkt)
{
	if (pkt->mask & SW_END_MASK) {
		if (qp_type(qp) == IB_QPT_RC)
			wqe->state = wqe_state_pending;
	} else {
		wqe->state = wqe_state_processing;
	}
}

static void update_wqe_psn(struct sw_qp *qp,
			   struct sw_send_wqe *wqe,
			   struct sw_pkt_info *pkt,
			   int payload)
{
	/* number of packets left to send including current one */
	int num_pkt = (wqe->dma.resid + payload + qp->mtu - 1) / qp->mtu;

	/* handle zero length packet case */
	if (num_pkt == 0)
		num_pkt = 1;

	if (pkt->mask & SW_START_MASK) {
		wqe->first_psn = qp->req.psn;
		wqe->last_psn = (qp->req.psn + num_pkt - 1) & BTH_PSN_MASK;
	}

	if (pkt->mask & SW_READ_MASK)
		qp->req.psn = (wqe->first_psn + num_pkt) & BTH_PSN_MASK;
	else
		qp->req.psn = (qp->req.psn + 1) & BTH_PSN_MASK;
}

static void save_state(struct sw_send_wqe *wqe,
		       struct sw_qp *qp,
		       struct sw_send_wqe *rollback_wqe,
		       u32 *rollback_psn)
{
	rollback_wqe->state     = wqe->state;
	rollback_wqe->first_psn = wqe->first_psn;
	rollback_wqe->last_psn  = wqe->last_psn;
	*rollback_psn		= qp->req.psn;
}

static void rollback_state(struct sw_send_wqe *wqe,
			   struct sw_qp *qp,
			   struct sw_send_wqe *rollback_wqe,
			   u32 rollback_psn)
{
	wqe->state     = rollback_wqe->state;
	wqe->first_psn = rollback_wqe->first_psn;
	wqe->last_psn  = rollback_wqe->last_psn;
	qp->req.psn    = rollback_psn;
}

static void update_state(struct sw_qp *qp, struct sw_send_wqe *wqe,
			 struct sw_pkt_info *pkt, int payload)
{
	qp->req.opcode = pkt->opcode;

	if (pkt->mask & SW_END_MASK)
		qp->req.wqe_index = next_index(qp->sq.queue, qp->req.wqe_index);

	qp->need_req_skb = 0;

	if (qp->qp_timeout_jiffies && !timer_pending(&qp->retrans_timer))
		mod_timer(&qp->retrans_timer,
			  jiffies + qp->qp_timeout_jiffies);
}

int sw_requester(void *arg)
{
	struct sw_qp *qp = (struct sw_qp *)arg;
	struct sw_pkt_info pkt;
	struct sk_buff *skb;
	struct sw_send_wqe *wqe;
	enum sw_hdr_mask mask;
	int payload;
	int mtu;
	int opcode;
	int ret;
	struct sw_send_wqe rollback_wqe;
	u32 rollback_psn;

	sw_add_ref(qp);

next_wqe:
	if (unlikely(!qp->valid || qp->req.state == QP_STATE_ERROR))
		goto exit;

	if (unlikely(qp->req.state == QP_STATE_RESET)) {
		qp->req.wqe_index = consumer_index(qp->sq.queue);
		qp->req.opcode = -1;
		qp->req.need_rd_atomic = 0;
		qp->req.wait_psn = 0;
		qp->req.need_retry = 0;
		goto exit;
	}

	if (unlikely(qp->req.need_retry)) {
		req_retry(qp);
		qp->req.need_retry = 0;
	}

	wqe = req_next_wqe(qp);
	if (unlikely(!wqe))
		goto exit;

	if (wqe->mask & WR_REG_MASK) {
		if (wqe->wr.opcode == IB_WR_LOCAL_INV) {
			struct sw_dev *sw = to_rdev(qp->ibqp.device);
			struct sw_mem *rmr;

			rmr = sw_pool_get_index(&sw->mr_pool,
						 wqe->wr.ex.invalidate_rkey >> 8);
			if (!rmr) {
				pr_err("No mr for key %#x\n",
				       wqe->wr.ex.invalidate_rkey);
				wqe->state = wqe_state_error;
				wqe->status = IB_WC_MW_BIND_ERR;
				goto exit;
			}
			rmr->state = SW_MEM_STATE_FREE;
			sw_drop_ref(rmr);
			wqe->state = wqe_state_done;
			wqe->status = IB_WC_SUCCESS;
		} else if (wqe->wr.opcode == IB_WR_REG_MR) {
			struct sw_mem *rmr = to_rmr(wqe->wr.wr.reg.mr);

			rmr->state = SW_MEM_STATE_VALID;
			rmr->access = wqe->wr.wr.reg.access;
			rmr->ibmr.lkey = wqe->wr.wr.reg.key;
			rmr->ibmr.rkey = wqe->wr.wr.reg.key;
			rmr->iova = wqe->wr.wr.reg.mr->iova;
			wqe->state = wqe_state_done;
			wqe->status = IB_WC_SUCCESS;
		} else {
			goto exit;
		}
		if ((wqe->wr.send_flags & IB_SEND_SIGNALED) ||
		    qp->sq_sig_type == IB_SIGNAL_ALL_WR)
			sw_run_task(&qp->comp.task, 1);
		qp->req.wqe_index = next_index(qp->sq.queue,
						qp->req.wqe_index);
		goto next_wqe;
	}

	if (unlikely(qp_type(qp) == IB_QPT_RC &&
		psn_compare(qp->req.psn, (qp->comp.psn +
				SW_MAX_UNACKED_PSNS)) > 0)) {
		qp->req.wait_psn = 1;
		goto exit;
	}

	/* Limit the number of inflight SKBs per QP */
	if (unlikely(atomic_read(&qp->skb_out) >
		     SW_INFLIGHT_SKBS_PER_QP_HIGH)) {
		qp->need_req_skb = 1;
		goto exit;
	}

	opcode = next_opcode(qp, wqe, wqe->wr.opcode);
	if (unlikely(opcode < 0)) {
		wqe->status = IB_WC_LOC_QP_OP_ERR;
		goto exit;
	}

	mask = sw_opcode[opcode].mask;
	if (unlikely(mask & SW_READ_OR_ATOMIC)) {
		if (check_init_depth(qp, wqe))
			goto exit;
	}

	mtu = get_mtu(qp);
	payload = (mask & SW_WRITE_OR_SEND) ? wqe->dma.resid : 0;
	if (payload > mtu) {
		if (qp_type(qp) == IB_QPT_UD) {
			/* C10-93.1.1: If the total sum of all the buffer lengths specified for a
			 * UD message exceeds the MTU of the port as returned by QueryHCA, the CI
			 * shall not emit any packets for this message. Further, the CI shall not
			 * generate an error due to this condition.
			 */

			/* fake a successful UD send */
			wqe->first_psn = qp->req.psn;
			wqe->last_psn = qp->req.psn;
			qp->req.psn = (qp->req.psn + 1) & BTH_PSN_MASK;
			qp->req.opcode = IB_OPCODE_UD_SEND_ONLY;
			qp->req.wqe_index = next_index(qp->sq.queue,
						       qp->req.wqe_index);
			wqe->state = wqe_state_done;
			wqe->status = IB_WC_SUCCESS;
			__sw_do_task(&qp->comp.task);
			sw_drop_ref(qp);
			return 0;
		}
		payload = mtu;
	}

	skb = init_req_packet(qp, wqe, opcode, payload, &pkt);
	if (unlikely(!skb)) {
		pr_err("qp#%d Failed allocating skb\n", qp_num(qp));
		goto err;
	}

	if (fill_packet(qp, wqe, &pkt, skb, payload)) {
		pr_debug("qp#%d Error during fill packet\n", qp_num(qp));
		kfree_skb(skb);
		goto err;
	}

	/*
	 * To prevent a race on wqe access between requester and completer,
	 * wqe members state and psn need to be set before calling
	 * sw_xmit_packet().
	 * Otherwise, completer might initiate an unjustified retry flow.
	 */
	save_state(wqe, qp, &rollback_wqe, &rollback_psn);
	update_wqe_state(qp, wqe, &pkt);
	update_wqe_psn(qp, wqe, &pkt, payload);
	ret = sw_xmit_packet(qp, &pkt, skb);
	if (ret) {
		qp->need_req_skb = 1;
		pr_err("sw_xmit_packet %d", ret);

		rollback_state(wqe, qp, &rollback_wqe, rollback_psn);

		if (ret == -EAGAIN) {
			sw_run_task(&qp->req.task, 1);
			goto exit;
		}

		goto err;
	}

	update_state(qp, wqe, &pkt, payload);

	goto next_wqe;

err:
	wqe->status = IB_WC_LOC_PROT_ERR;
	wqe->state = wqe_state_error;
	__sw_do_task(&qp->comp.task);

exit:
	sw_drop_ref(qp);
	return -EAGAIN;
}
