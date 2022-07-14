// SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause

/* Authors: Cheng Xu <chengyou@linux.alibaba.com> */
/*          Kai Shen <kaishen@linux.alibaba.com> */
/* Copyright (c) 2020-2021, Alibaba Group */
/* Authors: Bernard Metzler <bmt@zurich.ibm.com> */
/* Copyright (c) 2008-2019, IBM Corporation */

#include "erdma_verbs.h"

extern bool compat_mode;

void erdma_qp_llp_close(struct erdma_qp *qp)
{
	struct erdma_qp_attrs qp_attrs;

	down_write(&qp->state_lock);

	switch (qp->attrs.state) {
	case ERDMA_QP_STATE_RTS:
	case ERDMA_QP_STATE_RTR:
	case ERDMA_QP_STATE_IDLE:
	case ERDMA_QP_STATE_TERMINATE:
		qp_attrs.state = ERDMA_QP_STATE_CLOSING;
		erdma_modify_qp_internal(qp, &qp_attrs, ERDMA_QP_ATTR_STATE);
		break;
	case ERDMA_QP_STATE_CLOSING:
		qp->attrs.state = ERDMA_QP_STATE_IDLE;
		break;
	default:
		break;
	}

	if (qp->cep) {
		erdma_cep_put(qp->cep);
		qp->cep = NULL;
	}

	up_write(&qp->state_lock);
}

struct ib_qp *erdma_get_ibqp(struct ib_device *ibdev, int id)
{
	struct erdma_qp *qp = find_qp_by_qpn(to_edev(ibdev), id);

	if (qp)
		return &qp->ibqp;

	return NULL;
}

static int erdma_modify_qp_state_to_rts(struct erdma_qp *qp,
					struct erdma_qp_attrs *attrs,
					enum erdma_qp_attr_mask mask)
{
	int ret;
	struct erdma_dev *dev = qp->dev;
	struct erdma_cmdq_modify_qp_req req;
	struct tcp_sock *tp;
	struct erdma_cep *cep = qp->cep;
	struct sockaddr_storage local_addr, remote_addr;

	if (qp->attrs.connect_without_cm) {
		req.cookie = qp->ibqp.qp_num;
		req.dip = htonl(qp->attrs.dip);
		req.sip = htonl(qp->attrs.sip);
		req.dport = htons(qp->attrs.dport);
		req.sport = htons(qp->attrs.sport);
		req.send_nxt = 0;
		req.recv_nxt = 0;
		goto without_cep;
	}
	if (!(mask & ERDMA_QP_ATTR_LLP_HANDLE))
		return -EINVAL;

	if (!(mask & ERDMA_QP_ATTR_MPA))
		return -EINVAL;

	ret = getname_local(cep->sock, &local_addr);
	if (ret < 0)
		return ret;

	ret = getname_peer(cep->sock, &remote_addr);
	if (ret < 0)
		return ret;

	tp = tcp_sk(qp->cep->sock->sk);

	qp->attrs.remote_cookie = be32_to_cpu(qp->cep->mpa.ext_data.cookie);

	req.cookie = be32_to_cpu(qp->cep->mpa.ext_data.cookie);
	req.dip = to_sockaddr_in(remote_addr).sin_addr.s_addr;
	req.sip = to_sockaddr_in(local_addr).sin_addr.s_addr;
	req.dport = to_sockaddr_in(remote_addr).sin_port;
	req.sport = to_sockaddr_in(local_addr).sin_port;

	req.send_nxt = tp->snd_nxt;
	/* rsvd tcp seq for mpa-rsp in server. */
	if (qp->attrs.qp_type == ERDMA_QP_PASSIVE)
		req.send_nxt += MPA_DEFAULT_HDR_LEN + qp->attrs.pd_len;
	req.recv_nxt = tp->rcv_nxt;

without_cep:

	qp->attrs.state = ERDMA_QP_STATE_RTS;

	erdma_cmdq_build_reqhdr(&req.hdr, CMDQ_SUBMOD_RDMA,
				CMDQ_OPCODE_MODIFY_QP);

	req.cfg = FIELD_PREP(ERDMA_CMD_MODIFY_QP_STATE_MASK, qp->attrs.state) |
		  FIELD_PREP(ERDMA_CMD_MODIFY_QP_CC_MASK, qp->attrs.cc) |
		  FIELD_PREP(ERDMA_CMD_MODIFY_QP_QPN_MASK, QP_ID(qp));

	return erdma_post_cmd_wait(&dev->cmdq, (u64 *)&req, sizeof(req), NULL,
				   NULL);
}

static int erdma_modify_qp_state_to_rts_compat(struct erdma_qp *qp,
					       struct erdma_qp_attrs *attrs,
					       enum erdma_qp_attr_mask mask)
{
	struct erdma_dev *dev = qp->dev;
	struct erdma_cmdq_modify_qp_req req;

	qp->attrs.state = ERDMA_QP_STATE_RTS;

	erdma_cmdq_build_reqhdr(&req.hdr, CMDQ_SUBMOD_RDMA,
				CMDQ_OPCODE_MODIFY_QP);

	req.cfg = FIELD_PREP(ERDMA_CMD_MODIFY_QP_STATE_MASK, qp->attrs.state) |
		  FIELD_PREP(ERDMA_CMD_MODIFY_QP_CC_MASK, qp->attrs.cc) |
		  FIELD_PREP(ERDMA_CMD_MODIFY_QP_QPN_MASK, QP_ID(qp));

	req.cookie = qp->attrs.remote_qp_num;
	req.dip = qp->attrs.raddr.in.sin_addr.s_addr;
	req.sip = qp->attrs.laddr.in.sin_addr.s_addr;

	if (req.dip < req.sip) {
		req.dport = COMPAT_PORT_BASE +
			    ((QP_ID(qp) >> 16) & 0xF);
		req.sport = QP_ID(qp);
	} else if (req.dip == req.sip) { /* if dip == sip, must have lqpn != rqpn */
		if (QP_ID(qp) < qp->attrs.remote_qp_num) {
			req.dport = COMPAT_PORT_BASE +
				((QP_ID(qp) >> 16) & 0xF);
			req.sport = QP_ID(qp);
		} else {
			req.sport = COMPAT_PORT_BASE +
				((qp->attrs.remote_qp_num >> 16) & 0xF);
			req.dport = qp->attrs.remote_qp_num;
		}
	} else {
		req.sport = COMPAT_PORT_BASE +
			    ((qp->attrs.remote_qp_num >> 16) & 0xF);
		req.dport = qp->attrs.remote_qp_num;
	}

	req.send_nxt = req.sport * 4;
	req.recv_nxt = req.dport * 4;

	return erdma_post_cmd_wait(&dev->cmdq, (u64 *)&req, sizeof(req), NULL,
				   NULL);
}

static int erdma_modify_qp_state_to_stop(struct erdma_qp *qp,
					 struct erdma_qp_attrs *attrs,
					 enum erdma_qp_attr_mask mask)
{
	struct erdma_dev *dev = qp->dev;
	struct erdma_cmdq_modify_qp_req req;

	qp->attrs.state = attrs->state;

	erdma_cmdq_build_reqhdr(&req.hdr, CMDQ_SUBMOD_RDMA,
				CMDQ_OPCODE_MODIFY_QP);

	req.cfg = FIELD_PREP(ERDMA_CMD_MODIFY_QP_STATE_MASK, attrs->state) |
		  FIELD_PREP(ERDMA_CMD_MODIFY_QP_QPN_MASK, QP_ID(qp));

	return erdma_post_cmd_wait(&dev->cmdq, (u64 *)&req, sizeof(req), NULL,
				   NULL);
}

int erdma_modify_qp_internal(struct erdma_qp *qp, struct erdma_qp_attrs *attrs,
			     enum erdma_qp_attr_mask mask)
{
	int drop_conn, ret = 0;

	if (!mask)
		return 0;

	if (!(mask & ERDMA_QP_ATTR_STATE))
		return 0;

	switch (qp->attrs.state) {
	case ERDMA_QP_STATE_IDLE:
	case ERDMA_QP_STATE_RTR:
		if (attrs->state == ERDMA_QP_STATE_RTS) {
			if (compat_mode)
				ret = erdma_modify_qp_state_to_rts_compat(qp, attrs, mask);
			else
				ret = erdma_modify_qp_state_to_rts(qp, attrs, mask);
		} else if (attrs->state == ERDMA_QP_STATE_ERROR) {
			qp->attrs.state = ERDMA_QP_STATE_ERROR;
			if (qp->cep) {
				erdma_cep_put(qp->cep);
				qp->cep = NULL;
			}

			ret = erdma_modify_qp_state_to_stop(qp, attrs, mask);
		}
		break;
	case ERDMA_QP_STATE_RTS:
		drop_conn = 0;

		if (attrs->state == ERDMA_QP_STATE_CLOSING ||
		    attrs->state == ERDMA_QP_STATE_TERMINATE ||
		    attrs->state == ERDMA_QP_STATE_ERROR) {
			drop_conn = 1;
			if (!(qp->attrs.flags & ERDMA_QP_IN_DESTROY))
				ret = erdma_modify_qp_state_to_stop(qp, attrs, mask);
		}

		if (drop_conn)
			erdma_qp_cm_drop(qp);

		break;
	case ERDMA_QP_STATE_TERMINATE:
		if (attrs->state == ERDMA_QP_STATE_ERROR)
			qp->attrs.state = ERDMA_QP_STATE_ERROR;
		break;
	case ERDMA_QP_STATE_CLOSING:
		if (attrs->state == ERDMA_QP_STATE_IDLE) {
			qp->attrs.state = ERDMA_QP_STATE_IDLE;
		} else if (attrs->state == ERDMA_QP_STATE_ERROR) {
			ret = erdma_modify_qp_state_to_stop(qp, attrs, mask);
			qp->attrs.state = ERDMA_QP_STATE_ERROR;
		} else if (attrs->state != ERDMA_QP_STATE_CLOSING) {
			return -ECONNABORTED;
		}
		break;
	default:
		break;
	}

	return ret;
}

static void erdma_qp_safe_free(struct kref *ref)
{
	struct erdma_qp *qp = container_of(ref, struct erdma_qp, ref);

	complete(&qp->safe_free);
}

void erdma_qp_put(struct erdma_qp *qp)
{
	WARN_ON(kref_read(&qp->ref) < 1);
	kref_put(&qp->ref, erdma_qp_safe_free);
}

void erdma_qp_get(struct erdma_qp *qp)
{
	kref_get(&qp->ref);
}

static int fill_inline_data(struct erdma_qp *qp,
			    const struct ib_send_wr *send_wr, u16 wqe_idx,
			    u32 sgl_offset, __le32 *length_field)
{
	u32 remain_size, copy_size, data_off, bytes = 0;
	char *data;
	int i = 0;

	wqe_idx += (sgl_offset >> SQEBB_SHIFT);
	sgl_offset &= (SQEBB_SIZE - 1);
	data = get_queue_entry(qp->kern_qp.sq_buf, wqe_idx, qp->attrs.sq_size,
			       SQEBB_SHIFT);

	while (i < send_wr->num_sge) {
		bytes += send_wr->sg_list[i].length;
		if (bytes > (int)ERDMA_MAX_INLINE)
			return -EINVAL;

		remain_size = send_wr->sg_list[i].length;
		data_off = 0;

		while (1) {
			copy_size = min(remain_size, SQEBB_SIZE - sgl_offset);

			memcpy(data + sgl_offset,
			       (void *)(uintptr_t)send_wr->sg_list[i].addr +
				       data_off,
			       copy_size);
			remain_size -= copy_size;
			data_off += copy_size;
			sgl_offset += copy_size;
			wqe_idx += (sgl_offset >> SQEBB_SHIFT);
			sgl_offset &= (SQEBB_SIZE - 1);

			data = get_queue_entry(qp->kern_qp.sq_buf, wqe_idx,
					       qp->attrs.sq_size, SQEBB_SHIFT);
			if (!remain_size)
				break;
		};

		i++;
	}
	*length_field = cpu_to_le32(bytes);

	return bytes;
}

static int fill_sgl(struct erdma_qp *qp, const struct ib_send_wr *send_wr,
		    u16 wqe_idx, u32 sgl_offset, __le32 *length_field)
{
	int i = 0;
	u32 bytes = 0;
	char *sgl;

	if (send_wr->num_sge > qp->dev->attrs.max_send_sge)
		return -EINVAL;

	if (sgl_offset & 0xF)
		return -EINVAL;

	while (i < send_wr->num_sge) {
		wqe_idx += (sgl_offset >> SQEBB_SHIFT);
		sgl_offset &= (SQEBB_SIZE - 1);
		sgl = get_queue_entry(qp->kern_qp.sq_buf, wqe_idx,
				      qp->attrs.sq_size, SQEBB_SHIFT);

		bytes += send_wr->sg_list[i].length;
		memcpy(sgl + sgl_offset, &send_wr->sg_list[i],
		       sizeof(struct ib_sge));

		sgl_offset += sizeof(struct ib_sge);
		i++;
	}

	*length_field = cpu_to_le32(bytes);
	return 0;
}

static int erdma_push_one_sqe(struct erdma_qp *qp, u16 *pi,
			      const struct ib_send_wr *send_wr)
{
	u32 wqe_size, wqebb_cnt, hw_op, flags, sgl_offset;
	u32 idx = *pi & (qp->attrs.sq_size - 1);
	enum ib_wr_opcode op = send_wr->opcode;
	struct erdma_readreq_sqe *read_sqe;
	struct erdma_reg_mr_sqe *regmr_sge;
	struct erdma_write_sqe *write_sqe;
	struct erdma_send_sqe *send_sqe;
	struct ib_rdma_wr *rdma_wr;
	struct erdma_mr *mr;
	__le32 *length_field;
	u64 wqe_hdr, *entry;
	struct ib_sge *sge;
	u32 attrs;
	int ret;

	entry = get_queue_entry(qp->kern_qp.sq_buf, idx, qp->attrs.sq_size,
				SQEBB_SHIFT);

	/* Clear the SQE header section. */
	*entry = 0;

	qp->kern_qp.swr_tbl[idx] = send_wr->wr_id;
	flags = send_wr->send_flags;
	wqe_hdr = FIELD_PREP(
		ERDMA_SQE_HDR_CE_MASK,
		((flags & IB_SEND_SIGNALED) || qp->kern_qp.sig_all) ? 1 : 0);
	wqe_hdr |= FIELD_PREP(ERDMA_SQE_HDR_SE_MASK,
			      flags & IB_SEND_SOLICITED ? 1 : 0);
	wqe_hdr |= FIELD_PREP(ERDMA_SQE_HDR_FENCE_MASK,
			      flags & IB_SEND_FENCE ? 1 : 0);
	wqe_hdr |= FIELD_PREP(ERDMA_SQE_HDR_INLINE_MASK,
			      flags & IB_SEND_INLINE ? 1 : 0);
	wqe_hdr |= FIELD_PREP(ERDMA_SQE_HDR_QPN_MASK, QP_ID(qp));

	switch (op) {
	case IB_WR_RDMA_WRITE:
	case IB_WR_RDMA_WRITE_WITH_IMM:
		hw_op = ERDMA_OP_WRITE;
		if (op == IB_WR_RDMA_WRITE_WITH_IMM)
			hw_op = ERDMA_OP_WRITE_WITH_IMM;
		wqe_hdr |= FIELD_PREP(ERDMA_SQE_HDR_OPCODE_MASK, hw_op);
		rdma_wr = container_of(send_wr, struct ib_rdma_wr, wr);
		write_sqe = (struct erdma_write_sqe *)entry;

		write_sqe->imm_data = send_wr->ex.imm_data;
		write_sqe->sink_stag = cpu_to_le32(rdma_wr->rkey);
		write_sqe->sink_to_h =
			cpu_to_le32(upper_32_bits(rdma_wr->remote_addr));
		write_sqe->sink_to_l =
			cpu_to_le32(lower_32_bits(rdma_wr->remote_addr));

		length_field = &write_sqe->length;
		wqe_size = sizeof(struct erdma_write_sqe);
		sgl_offset = wqe_size;
		break;
	case IB_WR_RDMA_READ:
	case IB_WR_RDMA_READ_WITH_INV:
		read_sqe = (struct erdma_readreq_sqe *)entry;
		if (unlikely(send_wr->num_sge != 1))
			return -EINVAL;
		hw_op = ERDMA_OP_READ;
		if (op == IB_WR_RDMA_READ_WITH_INV) {
			hw_op = ERDMA_OP_READ_WITH_INV;
			read_sqe->invalid_stag =
				cpu_to_le32(send_wr->ex.invalidate_rkey);
		}

		wqe_hdr |= FIELD_PREP(ERDMA_SQE_HDR_OPCODE_MASK, hw_op);
		rdma_wr = container_of(send_wr, struct ib_rdma_wr, wr);
		read_sqe->length = cpu_to_le32(send_wr->sg_list[0].length);
		read_sqe->sink_stag = cpu_to_le32(send_wr->sg_list[0].lkey);
		read_sqe->sink_to_l =
			cpu_to_le32(lower_32_bits(send_wr->sg_list[0].addr));
		read_sqe->sink_to_h =
			cpu_to_le32(upper_32_bits(send_wr->sg_list[0].addr));

		sge = get_queue_entry(qp->kern_qp.sq_buf, idx + 1,
				      qp->attrs.sq_size, SQEBB_SHIFT);
		sge->addr = rdma_wr->remote_addr;
		sge->lkey = rdma_wr->rkey;
		sge->length = send_wr->sg_list[0].length;
		wqe_size = sizeof(struct erdma_readreq_sqe) +
			   send_wr->num_sge * sizeof(struct ib_sge);

		goto out;
	case IB_WR_SEND:
	case IB_WR_SEND_WITH_IMM:
	case IB_WR_SEND_WITH_INV:
		send_sqe = (struct erdma_send_sqe *)entry;
		hw_op = ERDMA_OP_SEND;
		if (op == IB_WR_SEND_WITH_IMM) {
			hw_op = ERDMA_OP_SEND_WITH_IMM;
			send_sqe->imm_data = send_wr->ex.imm_data;
		} else if (op == IB_WR_SEND_WITH_INV) {
			hw_op = ERDMA_OP_SEND_WITH_INV;
			send_sqe->invalid_stag =
				cpu_to_le32(send_wr->ex.invalidate_rkey);
		}
		wqe_hdr |= FIELD_PREP(ERDMA_SQE_HDR_OPCODE_MASK, hw_op);
		length_field = &send_sqe->length;
		wqe_size = sizeof(struct erdma_send_sqe);
		sgl_offset = wqe_size;

		break;
	case IB_WR_REG_MR:
		wqe_hdr |=
			FIELD_PREP(ERDMA_SQE_HDR_OPCODE_MASK, ERDMA_OP_REG_MR);
		regmr_sge = (struct erdma_reg_mr_sqe *)entry;
		mr = to_emr(reg_wr(send_wr)->mr);

		mr->access = ERDMA_MR_ACC_LR |
			     to_erdma_access_flags(reg_wr(send_wr)->access);
		regmr_sge->addr = cpu_to_le64(mr->ibmr.iova);
		regmr_sge->length = cpu_to_le32(mr->ibmr.length);
		regmr_sge->stag = cpu_to_le32(reg_wr(send_wr)->key);
		attrs = FIELD_PREP(ERDMA_SQE_MR_MODE_MASK, 0) |
			FIELD_PREP(ERDMA_SQE_MR_ACCESS_MASK, mr->access) |
			FIELD_PREP(ERDMA_SQE_MR_MTT_CNT_MASK,
				   mr->mem.mtt_nents);

		if (mr->mem.mtt_nents < ERDMA_MAX_INLINE_MTT_ENTRIES) {
			attrs |= FIELD_PREP(ERDMA_SQE_MR_MTT_TYPE_MASK, 0);
			/* Copy SGLs to SQE content to accelerate */
			memcpy(get_queue_entry(qp->kern_qp.sq_buf, idx + 1,
					       qp->attrs.sq_size, SQEBB_SHIFT),
			       mr->mem.mtt_buf, MTT_SIZE(mr->mem.mtt_nents));
			wqe_size = sizeof(struct erdma_reg_mr_sqe) +
				   MTT_SIZE(mr->mem.mtt_nents);
		} else {
			attrs |= FIELD_PREP(ERDMA_SQE_MR_MTT_TYPE_MASK, 1);
			wqe_size = sizeof(struct erdma_reg_mr_sqe);
		}

		regmr_sge->attrs = cpu_to_le32(attrs);
		goto out;
	case IB_WR_LOCAL_INV:
		wqe_hdr |= FIELD_PREP(ERDMA_SQE_HDR_OPCODE_MASK,
				      ERDMA_OP_LOCAL_INV);
		regmr_sge = (struct erdma_reg_mr_sqe *)entry;
		regmr_sge->stag = cpu_to_le32(send_wr->ex.invalidate_rkey);
		wqe_size = sizeof(struct erdma_reg_mr_sqe);
		goto out;
	default:
		return -EOPNOTSUPP;
	}

	if (flags & IB_SEND_INLINE) {
		ret = fill_inline_data(qp, send_wr, idx, sgl_offset,
				       length_field);
		if (ret < 0)
			return -EINVAL;
		wqe_size += ret;
		wqe_hdr |= FIELD_PREP(ERDMA_SQE_HDR_SGL_LEN_MASK, ret);
	} else {
		ret = fill_sgl(qp, send_wr, idx, sgl_offset, length_field);
		if (ret)
			return -EINVAL;
		wqe_size += send_wr->num_sge * sizeof(struct ib_sge);
		wqe_hdr |= FIELD_PREP(ERDMA_SQE_HDR_SGL_LEN_MASK,
				      send_wr->num_sge);
	}

out:
	wqebb_cnt = SQEBB_COUNT(wqe_size);
	wqe_hdr |= FIELD_PREP(ERDMA_SQE_HDR_WQEBB_CNT_MASK, wqebb_cnt - 1);
	*pi += wqebb_cnt;
	wqe_hdr |= FIELD_PREP(ERDMA_SQE_HDR_WQEBB_INDEX_MASK, *pi);

	*entry = wqe_hdr;

	return 0;
}

static void kick_sq_db(struct erdma_qp *qp, u16 pi)
{
	u64 db_data = FIELD_PREP(ERDMA_SQE_HDR_QPN_MASK, QP_ID(qp)) |
		      FIELD_PREP(ERDMA_SQE_HDR_WQEBB_INDEX_MASK, pi);

	*(u64 *)qp->kern_qp.sq_db_info = db_data;
	writeq(db_data, qp->kern_qp.hw_sq_db);
}

#ifdef HAVE_POST_CONST_WR
static int erdma_post_send_internal(struct ib_qp *ibqp, const struct ib_send_wr *send_wr,
		    const struct ib_send_wr **bad_send_wr, bool is_last)
#else
static int erdma_post_send_internal(struct ib_qp *ibqp, struct ib_send_wr *send_wr,
		    struct ib_send_wr **bad_send_wr, bool is_last)
#endif
{
	struct erdma_qp *qp = to_eqp(ibqp);
	int ret = 0;
	const struct ib_send_wr *wr = send_wr;
	unsigned long flags;
	u16 sq_pi;

	if (!send_wr)
		return -EINVAL;

	spin_lock_irqsave(&qp->kern_qp.sq_lock, flags);
	if (unlikely(qp->kern_qp.sq_shutdown)) {
		*bad_send_wr = send_wr;
		ret = -EINVAL;
		goto out;
	}
	if (unlikely(is_last))
		qp->kern_qp.sq_shutdown = true;

	sq_pi = qp->kern_qp.sq_pi;

	while (wr) {
		if ((u16)(sq_pi - qp->kern_qp.sq_ci) >= qp->attrs.sq_size) {
			ret = -ENOMEM;
			*bad_send_wr = send_wr;
			break;
		}

		ret = erdma_push_one_sqe(qp, &sq_pi, wr);
		if (ret) {
			*bad_send_wr = wr;
			break;
		}
		qp->kern_qp.sq_pi = sq_pi;
		kick_sq_db(qp, sq_pi);

		wr = wr->next;
	}
out:
	spin_unlock_irqrestore(&qp->kern_qp.sq_lock, flags);

	return ret;
}

#ifdef HAVE_POST_CONST_WR
int erdma_post_send(struct ib_qp *ibqp, const struct ib_send_wr *send_wr,
		    const struct ib_send_wr **bad_send_wr)
#else
int erdma_post_send(struct ib_qp *ibqp, struct ib_send_wr *send_wr,
		    struct ib_send_wr **bad_send_wr)
#endif
{
	return erdma_post_send_internal(ibqp, send_wr, bad_send_wr, false);
}

static int erdma_post_recv_one(struct erdma_qp *qp,
			       const struct ib_recv_wr *recv_wr)
{
	struct erdma_rqe *rqe =
		get_queue_entry(qp->kern_qp.rq_buf, qp->kern_qp.rq_pi,
				qp->attrs.rq_size, RQE_SHIFT);

	rqe->qe_idx = cpu_to_le16(qp->kern_qp.rq_pi + 1);
	rqe->qpn = cpu_to_le32(QP_ID(qp));

	if (recv_wr->num_sge == 0) {
		rqe->length = 0;
	} else if (recv_wr->num_sge == 1) {
		rqe->stag = cpu_to_le32(recv_wr->sg_list[0].lkey);
		rqe->to = cpu_to_le64(recv_wr->sg_list[0].addr);
		rqe->length = cpu_to_le32(recv_wr->sg_list[0].length);
	} else {
		return -EINVAL;
	}

	*(u64 *)qp->kern_qp.rq_db_info = *(u64 *)rqe;
	writeq(*(u64 *)rqe, qp->kern_qp.hw_rq_db);

	qp->kern_qp.rwr_tbl[qp->kern_qp.rq_pi & (qp->attrs.rq_size - 1)] =
		recv_wr->wr_id;
	qp->kern_qp.rq_pi++;

	return 0;
}

#ifdef HAVE_POST_CONST_WR
static int erdma_post_recv_internal(struct ib_qp *ibqp, const struct ib_recv_wr *recv_wr,
		    const struct ib_recv_wr **bad_recv_wr, bool is_last)
#else
static int erdma_post_recv_internal(struct ib_qp *ibqp, struct ib_recv_wr *recv_wr,
		    struct ib_recv_wr **bad_recv_wr, bool is_last)
#endif
{
	const struct ib_recv_wr *wr = recv_wr;
	struct erdma_qp *qp = to_eqp(ibqp);
	unsigned long flags;
	int ret = 0;

	spin_lock_irqsave(&qp->kern_qp.rq_lock, flags);
	if (unlikely(qp->kern_qp.rq_shutdown)) {
		*bad_recv_wr = recv_wr;
		ret = -EINVAL;
		goto out;
	}
	if (unlikely(is_last))
		qp->kern_qp.rq_shutdown = true;

	while (wr) {
		ret = erdma_post_recv_one(qp, wr);
		if (ret) {
			*bad_recv_wr = wr;
			break;
		}
		wr = wr->next;
	}
out:
	spin_unlock_irqrestore(&qp->kern_qp.rq_lock, flags);
	return ret;
}

#ifdef HAVE_POST_CONST_WR
int erdma_post_recv(struct ib_qp *ibqp, const struct ib_recv_wr *recv_wr,
		    const struct ib_recv_wr **bad_recv_wr)
#else
int erdma_post_recv(struct ib_qp *ibqp, struct ib_recv_wr *recv_wr,
		    struct ib_recv_wr **bad_recv_wr)
#endif
{
	return erdma_post_recv_internal(ibqp, recv_wr, bad_recv_wr, false);
}

struct ib_drain_cqe {
	struct ib_cqe cqe;
	struct completion done;
};

static void ib_drain_qp_done(struct ib_cq *cq, struct ib_wc *wc)
{
	struct ib_drain_cqe *cqe = container_of(wc->wr_cqe, struct ib_drain_cqe,
						cqe);

	complete(&cqe->done);
}

static void erdma_drain_qp(struct ib_qp *qp)
{
	struct ib_drain_cqe sdrain;
	struct ib_drain_cqe rdrain;
	struct ib_recv_wr rwr = {};
	struct ib_qp_attr attr = { .qp_state = IB_QPS_ERR };
	struct ib_rdma_wr swr = {
		.wr = {
			.next = NULL,
			{ .wr_cqe   = &sdrain.cqe, },
			.opcode = IB_WR_RDMA_WRITE,
			.send_flags = IB_SEND_SIGNALED,
		},
	};
	int ret;
	int cnt;

	rwr.wr_cqe = &rdrain.cqe;
	rdrain.cqe.done = ib_drain_qp_done;
	init_completion(&rdrain.done);

	ret = erdma_post_recv_internal(qp, &rwr, NULL, true);
	if (ret) {
		WARN_ONCE(ret, "failed to drain recv queue: %d", ret);
		return;
	}

	sdrain.cqe.done = ib_drain_qp_done;
	init_completion(&sdrain.done);

	ret = erdma_post_send_internal(qp, &swr.wr, NULL, true);
	if (ret) {
		WARN_ONCE(ret, "failed to drain send queue: %d", ret);
		return;
	}

	ret = ib_modify_qp(qp, &attr, IB_QP_STATE);
	if (ret) {
		WARN_ONCE(ret, "failed to modify qp to ERR: %d", ret);
		return;
	}

	cnt = 0;
	while (wait_for_completion_timeout(&sdrain.done, HZ / 10) <= 0 && cnt < 50) {
		ib_process_cq_direct(qp->send_cq, -1);
		cnt++;
	}

	cnt = 0;
	while (wait_for_completion_timeout(&rdrain.done, HZ / 10) <= 0 && cnt < 50) {
		ib_process_cq_direct(qp->recv_cq, -1);
		cnt++;
	}
}

void erdma_drain_rq(struct ib_qp *ibqp)
{
	struct erdma_qp *qp = to_eqp(ibqp);

	if (qp->attrs.state != ERDMA_QP_STATE_ERROR)
		erdma_drain_qp(ibqp);
}

void erdma_drain_sq(struct ib_qp *ibqp)
{
	struct erdma_qp *qp = to_eqp(ibqp);

	if (qp->attrs.state != ERDMA_QP_STATE_ERROR)
		erdma_drain_qp(ibqp);
}
