// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB

/* Authors: Cheng Xu <chengyou@linux.alibaba.com> */
/* Copyright (c) 2020-2022, Alibaba Group. */

#include <linux/cdev.h>
#include <linux/sched.h>
#ifdef HAVE_HEADER_LINUX_SCHED_TASK
#include <linux/sched/task.h>
#endif
#include <linux/mm.h>
#include <rdma/ib_umem.h>

#include "erdma.h"
#include "erdma_cm.h"
#include "erdma_ioctl.h"
#include "erdma_verbs.h"

static struct class *erdma_chrdev_class;
static struct cdev erdma_cdev;
static struct device *erdma_chrdev;
static dev_t erdma_char_dev;

#define ERDMA_CHRDEV_NAME "erdma"

static int erdma_query_qpc(struct erdma_dev *dev, u32 qpn, void *out)
{
	BUILD_BUG_ON(sizeof(struct erdma_cmdq_query_qpc_resp) >
		     ERDMA_HW_RESP_SIZE);

	return erdma_query_resource(dev, CMDQ_SUBMOD_RDMA,
				    CMDQ_OPCODE_QUERY_QPC, qpn, out,
				    sizeof(struct erdma_cmdq_query_qpc_resp));
}

static int erdma_query_cqc(struct erdma_dev *dev, u32 cqn, void *out)
{
	BUILD_BUG_ON(sizeof(struct erdma_cmdq_query_cqc_resp) >
		     ERDMA_HW_RESP_SIZE);

	return erdma_query_resource(dev, CMDQ_SUBMOD_RDMA,
				    CMDQ_OPCODE_QUERY_CQC, cqn, out,
				    sizeof(struct erdma_cmdq_query_cqc_resp));
}

static int erdma_query_eqc(struct erdma_dev *dev, u32 eqn, void *out)
{
	BUILD_BUG_ON(sizeof(struct erdma_cmdq_query_eqc_resp) >
		     ERDMA_HW_RESP_SIZE);

	return erdma_query_resource(dev, CMDQ_SUBMOD_COMMON,
				    CMDQ_OPCODE_QUERY_EQC, eqn, out,
				    sizeof(struct erdma_cmdq_query_eqc_resp));
}

static int erdma_ioctl_conf_cmd(struct erdma_dev *edev,
				struct erdma_ioctl_msg *msg)
{
	int ret = 0;

	if (msg->in.opcode == ERDMA_CONFIG_TYPE_CC) {
		if (msg->in.config_req.is_set)
			edev->attrs.cc = msg->in.config_req.value;
		else
			msg->out.config_resp.value = edev->attrs.cc;
	} else if (msg->in.opcode == ERDMA_CONFIG_TYPE_RETRANS_NUM) {
		if (msg->in.config_req.is_set)
			ret = erdma_set_retrans_num(edev, msg->in.config_req.value);
		else
			msg->out.config_resp.value = edev->attrs.retrans_num;
	} else if (msg->in.opcode == ERDMA_CONFIG_TYPE_DACK_COUNT) {
		if (msg->in.config_req.is_set)
			ret = erdma_set_dack_count(edev, msg->in.config_req.value);
		else
			ret = -EINVAL;
	} else if (msg->in.opcode == ERDMA_CONFIG_TYPE_LEGACY_MODE) {
		if (msg->in.config_req.is_set)
			ret = erdma_enable_legacy_mode(edev, msg->in.config_req.value);
		else
			ret = -EINVAL;
	}

	msg->out.length = 4;
	return ret;
}


static void fill_eq_info(struct erdma_dev *dev, struct erdma_eq_info *info,
			 struct erdma_eq *eq)
{
	struct erdma_cmdq_query_eqc_resp resp;
	int ret;

	info->event_cnt = atomic64_read(&eq->event_num);
	info->notify_cnt = atomic64_read(&eq->notify_num);
	info->depth = eq->depth;
	info->ci = eq->ci;
	info->qbuf_dma = eq->qbuf_dma_addr;
	info->qbuf_va = (u64)eq->qbuf;
	info->hw_info_valid = 0;

	ret = erdma_query_eqc(dev, info->eqn, &resp);
	if (ret)
		return;

	info->hw_info_valid = 1;
	info->hw_depth = resp.depth;
	info->vector = resp.vector;
	info->int_suppression = resp.int_suppression;
	info->tail_owner = resp.tail_owner;
	info->head_owner = resp.head_owner;
	info->overflow = resp.overflow;
	info->head = resp.head;
	info->tail = resp.tail;
	info->cn_addr = resp.cn_addr;
	info->cn_db_addr = resp.cn_db_addr;
	info->eq_db_record = resp.eq_db_record;
}

static void show_cep_info(struct erdma_dev *edev)
{
	u64 num_cep = atomic_read(&edev->num_cep);
	struct list_head *pos, *tmp;

	pr_info("%s: %llu CEPs\n", edev->ibdev.name, num_cep);

	if (!num_cep)
		return;

	pr_info("%-20s%-6s%-6s%-7s%-3s%-3s%-4s%-21s%-9s\n", "CEP", "State",
		"Ref's", "QP-ID", "LQ", "LC", "U", "Sock", "CM-ID");

	list_for_each_safe(pos, tmp, &edev->cep_list) {
		struct erdma_cep *cep = list_entry(pos, struct erdma_cep, devq);

		pr_info("0x%-18p%-6d%-6d%-7d%-3s%-3s%-4d0x%-18p 0x%-16p\n", cep,
			cep->state, kref_read(&cep->ref),
			cep->qp ? QP_ID(cep->qp) : -1,
			list_empty(&cep->listenq) ? "n" : "y",
			cep->listen_cep ? "y" : "n", cep->in_use, cep->sock,
			cep->cm_id);
	}
}

static int fill_cq_info(struct erdma_dev *dev, u32 cqn,
			struct erdma_ioctl_msg *msg)
{
	struct erdma_cq_info *info = &msg->out.cq_info;
	struct erdma_cmdq_query_cqc_resp resp;
#ifdef HAVE_RDMA_RESTRACK_ENTRY_USER
	struct rdma_restrack_entry *res;
#endif
	struct erdma_cq *cq;
	int ret;

	if (cqn == 0) {
		info->cqn = 0;
		info->depth = dev->cmdq.cq.depth;
		info->assoc_eqn = 0;
		info->qbuf_dma_addr = dev->cmdq.cq.qbuf_dma_addr;
		info->ci = dev->cmdq.cq.ci;
		info->cmdsn = dev->cmdq.cq.cmdsn;
		info->notify_cnt = atomic64_read(&dev->cmdq.cq.armed_num);

		goto query_hw_cqc;
	}

	cq = find_cq_by_cqn(dev, cqn);
	if (!cq)
		return -EINVAL;

	info->cqn = cq->cqn;
	info->depth = cq->depth;
	info->assoc_eqn = cq->assoc_eqn;

#ifdef HAVE_RDMA_RESTRACK_ENTRY_USER
	res = &cq->ibcq.res;
	info->is_user = !rdma_is_kernel_res(res);
#else
	info->is_user = cq->user;
#endif

	if (info->is_user) {
		info->mtt.page_size = cq->user_cq.qbuf_mtt.page_size;
		info->mtt.page_offset = cq->user_cq.qbuf_mtt.page_offset;
		info->mtt.page_cnt = cq->user_cq.qbuf_mtt.page_cnt;
		info->mtt.mtt_nents = cq->user_cq.qbuf_mtt.mtt_nents;
		//memcpy(info->mtt.mtt_entry, cq->user_cq.qbuf_mtt.mtt_entry,
		//       ERDMA_MAX_INLINE_MTT_ENTRIES * sizeof(__u64));
		info->mtt.va = cq->user_cq.qbuf_mtt.va;
		info->mtt.len = cq->user_cq.qbuf_mtt.len;
//		info->mtt_type = cq->user_cq.qbuf_mtt.mtt_type;
	} else {
		info->qbuf_dma_addr = cq->kern_cq.qbuf_dma_addr;
		info->ci = cq->kern_cq.ci;
		info->cmdsn = cq->kern_cq.cmdsn;
		info->notify_cnt = cq->kern_cq.notify_cnt;
	}

	info->hw_info_valid = 0;

query_hw_cqc:
	ret = erdma_query_cqc(dev, cqn, &resp);
	if (ret)
		return 0;

	info->hw_info_valid = 1;
	info->hw_pi = resp.pi;
	info->enable = resp.q_en;
	info->log_depth = resp.log_depth;
	info->cq_cur_ownership = resp.cq_cur_ownership;
	info->last_errdb_type = resp.last_errdb_type;
	info->last_errdb_ci = resp.last_errdb_ci;
	info->out_order_db_cnt = resp.out_order_db_cnt;
	info->dup_db_cnt = resp.dup_db_cnt;
	info->cn_cq_db_addr = resp.cn_cq_db_addr;
	info->cq_db_record = resp.cq_db_record;

#if 0
	pr_info("cqn:%u, hw_reported_cnt:%llx, sw_reported_cnt:%llx.\n", cqn,
		atomic64_read(&cq->hw_reported_cnt),
		atomic64_read(&cq->sw_reported_cnt));

	pr_info("last pi:%x\n", cq->last_pi);
#endif
	return 0;
}

static int fill_ext_attr_info(struct erdma_dev *dev,
			struct erdma_ioctl_msg *msg)
{
	struct erdma_ext_attr_info *info = &msg->out.ext_attr_info;
	struct erdma_cmdq_query_ext_attr_resp resp;
	int ret = 0;

	ret = erdma_query_ext_attr(dev, &resp);

	info->cap = dev->attrs.cap_flags;
	info->ext_cap = resp.cap_mask;
	info->attr_mask = resp.attr_mask;
	info->dack_count = resp.dack_count;

	return ret;
}

static int erdma_ioctl_ver_cmd(struct erdma_dev *edev,
			       struct erdma_ioctl_msg *msg)
{
	msg->out.version =
		ERDMA_MAJOR_VER << 16 | ERDMA_MEDIUM_VER << 8 | ERDMA_MINOR_VER;

	return 0;
}

static int erdma_fill_qp_info(struct erdma_dev *dev, u32 qpn,
			      struct erdma_qp_info *qp_info)
{
	struct erdma_cmdq_query_qpc_resp resp;
#ifdef HAVE_RDMA_RESTRACK_ENTRY_USER
	struct rdma_restrack_entry *res;
#endif
	struct erdma_mem *mtt;
	struct erdma_qp *qp;
	int ret;

	if (qpn == 0)
		goto query_hw_qpc;

	qp = find_qp_by_qpn(dev, qpn);
	if (!qp)
		return -EINVAL;

	if (qp->ibqp.qp_type != IB_QPT_RC) {
		return -EINVAL;
	}

	erdma_qp_get(qp);

	qp_info->hw_info_valid = 0;
	qp_info->qpn = qp->ibqp.qp_num;
	qp_info->qp_state = qp->attrs.state;
	qp_info->ref_cnt = kref_read(&qp->ref);
	qp_info->qtype = qp->attrs.qp_type;
	qp_info->sq_depth = qp->attrs.sq_size;
	qp_info->rq_depth = qp->attrs.rq_size;
	qp_info->cookie = qp->attrs.remote_cookie;
	qp_info->cc = qp->attrs.cc;
	qp_info->assoc_scqn = qp->scq->cqn;
	qp_info->assoc_rcqn = qp->rcq->cqn;

	if (qp->cep && qp->cep->cm_id) {
		struct erdma_cep *cep = qp->cep;
		struct iw_cm_id *id = cep->cm_id;
		struct sockaddr_storage remote_addr;
		struct sockaddr_storage local_addr;

		qp_info->sip =
			ntohl(to_sockaddr_in(id->local_addr).sin_addr.s_addr);
		qp_info->dip =
			ntohl(to_sockaddr_in(id->remote_addr).sin_addr.s_addr);
		qp_info->sport = ntohs(to_sockaddr_in(id->local_addr).sin_port);
		qp_info->dport =
			ntohs(to_sockaddr_in(id->remote_addr).sin_port);

		if (cep->sock) {
			getname_local(cep->sock, &local_addr);
			getname_peer(cep->sock, &remote_addr);
			qp_info->origin_sport =
				ntohs(to_sockaddr_in(local_addr).sin_port);
			qp_info->sip = ntohl(
				to_sockaddr_in(local_addr).sin_addr.s_addr);
		}
	}

#ifdef HAVE_RDMA_RESTRACK_ENTRY_USER
	res = &qp->ibqp.res;
	qp_info->is_user = !rdma_is_kernel_res(res);
	if (qp_info->is_user) {
		qp_info->pid = res->task->pid;
		get_task_comm(qp_info->buf, res->task);
#else
	qp_info->is_user = qp->user;
	if (qp->user) {
#endif
		mtt = &qp->user_qp.sq_mtt;
//		qp_info->sq_mtt_type = mtt->mtt_type;
		qp_info->sq_mtt.page_size = mtt->page_size;
		qp_info->sq_mtt.page_offset = mtt->page_offset;
		qp_info->sq_mtt.page_cnt = mtt->page_cnt;
		qp_info->sq_mtt.mtt_nents = mtt->mtt_nents;
		qp_info->sq_mtt.va = mtt->va;
		qp_info->sq_mtt.len = mtt->len;
//		for (i = 0; i < ERDMA_MAX_INLINE_MTT_ENTRIES; i++)
//			qp_info->sq_mtt.mtt_entry[i] = mtt->mtt_entry[i];

		mtt = &qp->user_qp.rq_mtt;
//		qp_info->rq_mtt_type = mtt->mtt_type;
		qp_info->rq_mtt.page_size = mtt->page_size;
		qp_info->rq_mtt.page_offset = mtt->page_offset;
		qp_info->rq_mtt.page_cnt = mtt->page_cnt;
		qp_info->rq_mtt.mtt_nents = mtt->mtt_nents;
		qp_info->rq_mtt.va = mtt->va;
		qp_info->rq_mtt.len = mtt->len;
//		for (i = 0; i < ERDMA_MAX_INLINE_MTT_ENTRIES; i++)
//			qp_info->rq_mtt.mtt_entry[i] = mtt->mtt_entry[i];
	} else {
		qp_info->sqci = qp->kern_qp.sq_ci;
		qp_info->sqpi = qp->kern_qp.sq_pi;
		qp_info->rqci = qp->kern_qp.rq_ci;
		qp_info->rqpi = qp->kern_qp.rq_pi;

		qp_info->sqbuf_dma = qp->kern_qp.sq_buf_dma_addr;
		qp_info->rqbuf_dma = qp->kern_qp.rq_buf_dma_addr;
		qp_info->sqdbrec_dma = qp->kern_qp.sq_db_info_dma_addr;
		qp_info->rqdbrec_dma = qp->kern_qp.rq_db_info_dma_addr;
	}

	erdma_qp_put(qp);

query_hw_qpc:
	ret = erdma_query_qpc(dev, qpn, &resp);
	if (ret)
		return 0;

	qp_info->hw_info_valid = 1;
	qp_info->sq_enable = resp.qpc[0].status;
	qp_info->sqbuf_page_offset = resp.qpc[0].qbuf_page_offset;
	qp_info->sqbuf_page_size = resp.qpc[0].qbuf_page_size;
	qp_info->sqbuf_depth = resp.qpc[0].qbuf_depth;
	qp_info->hw_sq_ci = resp.qpc[0].hw_ci;
	qp_info->hw_sq_pi = resp.qpc[0].hw_pi;

	qp_info->rq_enable = resp.qpc[1].status;
	qp_info->rqbuf_page_offset = resp.qpc[1].qbuf_page_offset;
	qp_info->rqbuf_page_size = resp.qpc[1].qbuf_page_size;
	qp_info->rqbuf_depth = resp.qpc[1].qbuf_depth;
	qp_info->hw_rq_ci = resp.qpc[1].hw_ci;
	qp_info->hw_rq_pi = resp.qpc[1].hw_pi;
	qp_info->last_comp_sqe_idx = resp.last_comp_sqe_idx;
	qp_info->last_comp_rqe_idx = resp.last_comp_rqe_idx;
	qp_info->scqe_counter = resp.scqe_counter;
	qp_info->rcqe_counter = resp.rcqe_counter;
	qp_info->tx_pkts_cnt = resp.tx_pkts_cnt;
	qp_info->rx_pkts_cnt = resp.rx_pkts_cnt;
	qp_info->rx_error_drop_cnt = resp.rx_error_drop_cnt;
	qp_info->rx_invalid_drop_cnt = resp.rx_invalid_drop_cnt;
	qp_info->rto_retrans_cnt = resp.rto_retrans_cnt;
	qp_info->pd = resp.pd;
	qp_info->fw_sq_pi = resp.fw_sq_pi;
	qp_info->fw_sq_ci = resp.fw_sq_ci;
	qp_info->fw_rq_ci = resp.fw_rq_ci;
	qp_info->sq_in_flush = resp.sq_in_flush;
	qp_info->rq_in_flush = resp.rq_in_flush;
	qp_info->sq_flushed_pi = resp.sq_flushed_pi;
	qp_info->rq_flushed_pi = resp.rq_flushed_pi;
	qp_info->sqbuf_addr = resp.sqbuf_addr;
	qp_info->rqbuf_addr = resp.rqbuf_addr;
	qp_info->sdbrec_addr = resp.sdbrec_addr;
	qp_info->rdbrec_addr = resp.rdbrec_addr;
	qp_info->ip_src = resp.ip_src;
	qp_info->ip_dst = resp.ip_dst;
	qp_info->srcport = resp.srcport;
	qp_info->dstport = resp.dstport;
	qp_info->sdbrec_val = resp.sdbrec_cur;
	qp_info->rdbrec_val = resp.rdbrec_cur;

	if (qpn != 0 && resp.scqn != qp_info->assoc_scqn)
		ibdev_info(&dev->ibdev, "hw scqn(%u) != drv scqn(%u)\n",
			   resp.scqn, qp_info->assoc_scqn);

	if (qpn != 0 && resp.rcqn != qp_info->assoc_rcqn)
		ibdev_info(&dev->ibdev, "hw rcqn(%u) != drv rcqn(%u)\n",
			   resp.rcqn, qp_info->assoc_rcqn);

	return 0;
}

static int erdma_ioctl_info_cmd(struct erdma_dev *edev,
				struct erdma_ioctl_msg *msg)
{
	struct erdma_qp_info *qp_info;
	int ret = 0, count = 0, i;
#ifdef HAVE_XARRAY_API
	struct erdma_qp *qp;
	struct erdma_cq *cq;
	unsigned long index;
#else
	void *entry;
	int index;
#endif

	switch (msg->in.opcode) {
	case ERDMA_INFO_TYPE_QP:
		qp_info = &msg->out.qp_info;
		ret = erdma_fill_qp_info(edev, msg->in.info_req.qn, qp_info);

		break;
	case ERDMA_INFO_TYPE_ALLOCED_QP:
#ifdef HAVE_XARRAY_API
		xa_for_each_start(&edev->qp_xa, index, qp,
				   msg->in.info_req.qn) {
#else
		idr_for_each_entry(&edev->qp_idr, entry, index) {
			if (index < msg->in.info_req.qn)
				continue;
#endif
			msg->out.allocted_qpn[count++] = index;
			if (count == msg->in.info_req.max_result_cnt)
				break;
		}
		msg->out.length = count * 4;
		break;
	case ERDMA_INFO_TYPE_ALLOCED_CQ:
#ifdef HAVE_XARRAY_API
		xa_for_each_start(&edev->cq_xa, index, cq,
				   msg->in.info_req.qn) {
#else
		idr_for_each_entry(&edev->cq_idr, entry, index) {
			if (index < msg->in.info_req.qn)
				continue;
#endif
			msg->out.allocted_cqn[count++] = index;
			if (count == msg->in.info_req.max_result_cnt)
				break;
		}
		msg->out.length = count * 4;

		break;
	case ERDMA_INFO_TYPE_EQ:
		msg->out.eq_info[0].ready = 1;
		msg->out.eq_info[0].eqn = 0;
		fill_eq_info(edev, &msg->out.eq_info[0], &edev->aeq);

		msg->out.eq_info[1].ready = 1;
		msg->out.eq_info[1].eqn = 1;
		fill_eq_info(edev, &msg->out.eq_info[1], &edev->cmdq.eq);

		for (i = 0; i < 31; i++) {
			msg->out.eq_info[i + 2].ready = edev->ceqs[i].ready;
			msg->out.eq_info[i + 2].eqn = i + 2;
			fill_eq_info(edev, &msg->out.eq_info[i + 2],
				     &edev->ceqs[i].eq);
		}
		break;
	case ERDMA_INFO_TYPE_CEP:
		show_cep_info(edev);
		break;
	case ERDMA_INFO_TYPE_CQ:
		ret = fill_cq_info(edev, msg->in.info_req.qn, msg);
		break;
	case ERDMA_INFO_TYPE_EXT_ATTR:
		ret = fill_ext_attr_info(edev, msg);
		break;
	default:
		pr_info("unknown opcode:%u\n", msg->in.opcode);
		return -EINVAL;
	}

	return ret;
}

int erdma_ioctl_stat_cmd(struct erdma_dev *edev, struct erdma_ioctl_msg *msg)
{
	int ret;

	switch (msg->in.opcode) {
	case ERDMA_STAT_TYPE_QP:
	case ERDMA_STAT_TYPE_CQ:
		break;
	case ERDMA_STAT_TYPE_DEV:
		ret = erdma_query_hw_stats(edev);
		if (ret)
			return ret;

		/* Make sure that no overflow happens. */
		BUILD_BUG_ON(ERDMA_STATS_MAX > 512);

		memcpy(msg->out.stats, &edev->stats,
		       sizeof(__u64) * ERDMA_STATS_MAX);

		msg->out.length = ERDMA_STATS_MAX * sizeof(__u64);
		break;
	default:
		pr_err("unknown stat opcode %d.\n", msg->in.opcode);
		return -1;
	}

	return 0;
}

int erdma_ioctl_dump_cmd(struct erdma_dev *edev, struct erdma_ioctl_msg *msg)
{
	u32 qe_idx = msg->in.dump_req.qe_idx;
	u32 qn = msg->in.dump_req.qn;
	struct erdma_qp *qp;
	struct erdma_cq *cq;
	struct erdma_eq *eq;
	int ret = 0;
#if defined(HAVE_RDMA_RESTRACK_ENTRY_USER) && !defined(DISABLE_VM_ACCESS)
	u64 address;
#endif
	u32 wqe_idx;

	switch (msg->in.opcode) {
	case ERDMA_DUMP_TYPE_SQE:

		/* CMDQ-SQ */
		if (qn == 0) {
			wqe_idx = qe_idx & (edev->cmdq.sq.depth - 1);
			memcpy(msg->out.data,
			       edev->cmdq.sq.qbuf + (wqe_idx << SQEBB_SHIFT),
			       SQEBB_SIZE);
		} else {
			qp = find_qp_by_qpn(edev, qn);
			if (!qp)
				return -EINVAL;
			erdma_qp_get(qp);

#if defined(HAVE_RDMA_RESTRACK_ENTRY_USER) && !defined(DISABLE_VM_ACCESS)
			if (!rdma_is_kernel_res(&qp->ibqp.res)) {
				address = qp->user_qp.sq_mtt.umem->address;
				wqe_idx = qe_idx & (qp->attrs.sq_size - 1);
				address += wqe_idx << SQEBB_SHIFT;
				ret = access_process_vm(qp->ibqp.res.task,
							address, msg->out.data,
							SQEBB_SIZE, FOLL_FORCE);
				if (ret != SQEBB_SIZE) {
					pr_info("access address with error (%d)\n",
						ret);
					erdma_qp_put(qp);
					return -EIO;
				}
				ret = 0;
			} else {
				wqe_idx = qe_idx & (qp->attrs.sq_size - 1);
				memcpy(msg->out.data,
				       qp->kern_qp.sq_buf +
					       (wqe_idx << SQEBB_SHIFT),
				       SQEBB_SIZE);
			}
#else
			ret = -ENOTSUPP;
#endif
			erdma_qp_put(qp);
		}
		msg->out.length = SQEBB_SIZE;
		break;
	case ERDMA_DUMP_TYPE_RQE:
		qp = find_qp_by_qpn(edev, qn);
		if (!qp)
			return -EINVAL;
		erdma_qp_get(qp);

#if defined(HAVE_RDMA_RESTRACK_ENTRY_USER) && !defined(DISABLE_VM_ACCESS)
		if (!rdma_is_kernel_res(&qp->ibqp.res)) {
			address = qp->user_qp.rq_mtt.umem->address;
			wqe_idx = qe_idx & (qp->attrs.rq_size - 1);
			address += wqe_idx << RQE_SHIFT;
			ret = access_process_vm(qp->ibqp.res.task, address,
						msg->out.data, RQE_SIZE,
						FOLL_FORCE);
			if (ret != RQE_SIZE) {
				pr_info("access address with error (%d)\n",
					ret);
				erdma_qp_put(qp);
				return -EIO;
			}
			ret = 0;
		} else {
			wqe_idx = qe_idx & (qp->attrs.rq_size - 1);
			memcpy(msg->out.data,
			       qp->kern_qp.rq_buf + (wqe_idx << RQE_SHIFT),
			       RQE_SIZE);
		}
#else
		ret = -ENOTSUPP;
#endif
		erdma_qp_put(qp);
		msg->out.length = RQE_SIZE;
		break;
	case ERDMA_DUMP_TYPE_CQE:
		if (qn == 0) {
			/* CMDQ-CQ */
			wqe_idx = qe_idx & (edev->cmdq.cq.depth - 1);
			memcpy(msg->out.data,
			       edev->cmdq.cq.qbuf + (wqe_idx << CQE_SHIFT),
			       CQE_SIZE);
		} else {
			cq = find_cq_by_cqn(edev, qn);
			if (!cq)
				return -EINVAL;

#if defined(HAVE_RDMA_RESTRACK_ENTRY_USER) && !defined(DISABLE_VM_ACCESS)
			if (!rdma_is_kernel_res(&cq->ibcq.res)) {
				address = cq->user_cq.qbuf_mtt.umem->address;
				wqe_idx = qe_idx & (cq->depth - 1);
				address += wqe_idx << CQE_SHIFT;
				ret = access_process_vm(cq->ibcq.res.task,
							address, msg->out.data,
							CQE_SIZE, FOLL_FORCE);
				if (ret != CQE_SIZE) {
					pr_info("access address with error (%d)\n",
						ret);
					return -EIO;
				}
				ret = 0;
			} else {
				wqe_idx = qe_idx & (cq->depth - 1);
				memcpy(msg->out.data,
				       cq->kern_cq.qbuf +
					       (wqe_idx << CQE_SHIFT),
				       CQE_SIZE);
			}
#else
			ret = -ENOTSUPP;
#endif
		}
		msg->out.length = CQE_SIZE;
		break;

	case ERDMA_DUMP_TYPE_EQE:
		/* 0: AEQ, 1: CMD-EQ, 2 - 33: CEQ */
		if (qn == 0) { /* AEQ */
			eq = &edev->aeq;
		} else if (qn == 1) {
			eq = &edev->cmdq.eq;
		} else if (qn > 1 && qn <= 33) {
			if (edev->ceqs[qn - 2].ready == 0)
				return -EINVAL;
			eq = &edev->ceqs[qn - 2].eq;
		} else {
			return -EINVAL;
		}

		wqe_idx = qe_idx & (eq->depth - 1);
		memcpy(msg->out.data, eq->qbuf + (wqe_idx << EQE_SHIFT),
		       EQE_SIZE);
		msg->out.length = EQE_SIZE;
		break;
	default:
		break;
	}

	return ret;
}

typedef int (*ioctl_proc)(struct erdma_dev *, struct erdma_ioctl_msg *);

static const ioctl_proc erdma_ioctl_proc_table[EADM_CMD_MAX] = {
	[EADM_DUMP_CMD] = erdma_ioctl_dump_cmd,
	[EADM_INFO_CMD] = erdma_ioctl_info_cmd,
	[EADM_CONF_CMD] = erdma_ioctl_conf_cmd,
	[EADM_STAT_CMD] = erdma_ioctl_stat_cmd,
	[EADM_VER_CMD] = erdma_ioctl_ver_cmd,
};

long do_ioctl(unsigned int cmd, unsigned long arg)
{
	struct erdma_dev *edev = NULL;
	struct ib_device *ibdev = NULL;
	struct erdma_ioctl_msg *msg;
	int ret = 0, bypass_dev = 0;
	int command;

	msg = kzalloc(sizeof(*msg), GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	ret = copy_from_user(msg, (const void *)arg,
			     sizeof(struct erdma_ioctl_msg));
	if (ret) {
		kfree(msg);
		return -EINVAL;
	}

	if (_IOC_TYPE(cmd) != ERDMA_IOC_MAGIC ||
	    _IOC_NR(cmd) > ERDMA_IOC_MAXNR) {
		kfree(msg);
		return -EINVAL;
	}

	command = _IOC_NR(cmd);
	if (command >= EADM_CMD_MAX || !erdma_ioctl_proc_table[command]) {
		ret = -EINVAL;
		goto out;
	}

	/* 允许某些命令在没有ibdev的情况下执行 */
	if (command == EADM_VER_CMD)
		bypass_dev = 1;

	if (bypass_dev)
		goto exec_cmd;

	ibdev = ib_device_get_by_name(msg->in.ibdev_name, RDMA_DRIVER_ERDMA);
	if (ibdev) {
		edev = to_edev(ibdev);
	} else {
		kfree(msg);
		return -ENODEV;
	}

exec_cmd:
	msg->out.status = erdma_ioctl_proc_table[command](edev, msg);

	ret = copy_to_user((void *)arg, (const void *)msg,
			   sizeof(struct erdma_ioctl_msg));

out:
	if (!bypass_dev)
		ib_device_put(ibdev);

	kfree(msg);
	return ret;
}

long chardev_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	return do_ioctl(cmd, arg);
}

static char *erdma_chrdev_devnode(struct device *dev, umode_t *mode)
{
	if (mode)
		*mode = 0666;
	return kasprintf(GFP_KERNEL, "%s", dev_name(dev));
}

static int chardev_open(struct inode *inode, struct file *file)
{
	return 0;
}

static ssize_t chardev_read(struct file *file, char __user *buf, size_t size,
			    loff_t *ppos)
{
	return 0;
}

static int chardev_close(struct inode *inode, struct file *filp)
{
	return 0;
}

/* clang-format off */
static const struct file_operations chardev_fops = {
	.owner = THIS_MODULE,
	.open = chardev_open,
	.release = chardev_close,
	.read = chardev_read,
	.unlocked_ioctl = chardev_ioctl
};
/* clang-format on */

void erdma_chrdev_destroy(void)
{
	device_destroy(erdma_chrdev_class, erdma_char_dev);
	cdev_del(&erdma_cdev);
	class_destroy(erdma_chrdev_class);

	unregister_chrdev_region(erdma_char_dev, 1);
}

int erdma_chrdev_init(void)
{
	int ret;

	ret = alloc_chrdev_region(&erdma_char_dev, 0, 1, ERDMA_CHRDEV_NAME);
	if (ret) {
		pr_err("alloc chrdev failed.\n");
		return ret;
	}

	erdma_chrdev_class = class_create(THIS_MODULE, ERDMA_CHRDEV_NAME);
	if (IS_ERR(erdma_chrdev_class)) {
		ret = PTR_ERR(erdma_chrdev_class);
		pr_err("create class failed.\n");
		goto free_chrdev_region;
	}

	erdma_chrdev_class->devnode = erdma_chrdev_devnode;

	cdev_init(&erdma_cdev, &chardev_fops);
	erdma_cdev.owner = THIS_MODULE;
	ret = cdev_add(&erdma_cdev, erdma_char_dev, 1);
	if (ret) {
		pr_err("cdev add failed. ret = %d\n", ret);
		goto destroy_class;
	}

	erdma_chrdev = device_create(erdma_chrdev_class, NULL, erdma_char_dev,
				     NULL, ERDMA_CHRDEV_NAME);
	if (IS_ERR(erdma_chrdev)) {
		pr_err("create_device failed.\n");
		goto delete_cdev;
	}

	return 0;

delete_cdev:
	cdev_del(&erdma_cdev);

destroy_class:
	class_destroy(erdma_chrdev_class);

free_chrdev_region:
	unregister_chrdev_region(erdma_char_dev, 1);

	return ret;
}
