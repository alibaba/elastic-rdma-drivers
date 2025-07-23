#include <linux/skbuff.h>
#include <linux/delay.h>
#include <linux/sched.h>
#include <linux/vmalloc.h>
#include <rdma/uverbs_ioctl.h>

#include "sw.h"
#include "sw_loc.h"
#include "sw_queue.h"
#include "sw_task.h"
#include "../erdma_verbs.h"

static int sw_qp_chk_cap(struct sw_dev *sw, struct ib_qp_cap *cap,
			  int has_srq)
{
	if (cap->max_send_wr > sw->attr.max_qp_wr) {
		pr_warn("invalid send wr = %d > %d\n",
			cap->max_send_wr, sw->attr.max_qp_wr);
		goto err1;
	}
#ifdef HAVE_MAX_SEND_RCV_SGE
	if (cap->max_send_sge > sw->attr.max_send_sge) {
		pr_warn("invalid send sge = %d > %d\n",
			cap->max_send_sge, sw->attr.max_send_sge);
#else
	if (cap->max_send_sge > sw->attr.max_sge) {
		pr_warn("invalid send sge = %d > %d\n",
			cap->max_send_sge, sw->attr.max_sge);
#endif

		goto err1;
	}

	if (!has_srq) {
		if (cap->max_recv_wr > sw->attr.max_qp_wr) {
			pr_warn("invalid recv wr = %d > %d\n",
				cap->max_recv_wr, sw->attr.max_qp_wr);
			goto err1;
		}

#ifdef HAVE_MAX_SEND_RCV_SGE
		if (cap->max_recv_sge > sw->attr.max_recv_sge) {
			pr_warn("invalid recv sge = %d > %d\n",
				cap->max_recv_sge, sw->attr.max_recv_sge);
#else
		if (cap->max_recv_sge > sw->attr.max_sge) {
			pr_warn("invalid recv sge = %d > %d\n",
				cap->max_recv_sge, sw->attr.max_sge);
#endif
			goto err1;
		}
	}

	if (cap->max_inline_data > sw->max_inline_data) {
		pr_warn("invalid max inline data = %d > %d\n",
			cap->max_inline_data, sw->max_inline_data);
		goto err1;
	}

	return 0;

err1:
	return -EINVAL;
}

int sw_qp_chk_init(struct sw_dev *sw, struct ib_qp_init_attr *init)
{
	struct ib_qp_cap *cap = &init->cap;
	struct sw_port *port;
	int port_num = init->port_num;

	if (!init->recv_cq || !init->send_cq) {
		pr_warn("missing cq\n");
		goto err1;
	}

	if (sw_qp_chk_cap(sw, cap, !!init->srq))
		goto err1;

	if (init->qp_type == IB_QPT_SMI || init->qp_type == IB_QPT_GSI) {
		//if (!rdma_is_port_valid(&sw->ib_dev, port_num)) {
		//	pr_warn("invalid port = %d\n", port_num);
		//	goto err1;
		//}

		port = &sw->port;

		if (init->qp_type == IB_QPT_SMI && port->qp_smi_index) {
			pr_warn("SMI QP exists for port %d\n", port_num);
			goto err1;
		}

		if (init->qp_type == IB_QPT_GSI && port->qp_gsi_index) {
			pr_warn("GSI QP exists for port %d\n", port_num);
			goto err1;
		}
	}

	return 0;

err1:
	return -EINVAL;
}

static int alloc_rd_atomic_resources(struct sw_qp *qp, unsigned int n)
{
	qp->resp.res_head = 0;
	qp->resp.res_tail = 0;
	qp->resp.resources = kcalloc(n, sizeof(struct resp_res), GFP_KERNEL);

	if (!qp->resp.resources)
		return -ENOMEM;

	return 0;
}

void free_rd_atomic_resource(struct sw_qp *qp, struct resp_res *res)
{
	if (res->type == SW_ATOMIC_MASK) {
		kfree_skb(res->atomic.skb);
	} else if (res->type == SW_READ_MASK) {
		if (res->read.mr)
			sw_drop_ref(res->read.mr);
	}
	res->type = 0;
}

static void free_rd_atomic_resources(struct sw_qp *qp)
{
	if (qp->resp.resources) {
		int i;

		for (i = 0; i < qp->attr.max_dest_rd_atomic; i++) {
			struct resp_res *res = &qp->resp.resources[i];

			free_rd_atomic_resource(qp, res);
		}
		kfree(qp->resp.resources);
		qp->resp.resources = NULL;
	}
}

static void cleanup_rd_atomic_resources(struct sw_qp *qp)
{
	int i;
	struct resp_res *res;

	if (qp->resp.resources) {
		for (i = 0; i < qp->attr.max_dest_rd_atomic; i++) {
			res = &qp->resp.resources[i];
			free_rd_atomic_resource(qp, res);
		}
	}
}

static void sw_qp_init_misc(struct sw_dev *sw, struct sw_qp *qp,
			     struct ib_qp_init_attr *init)
{
	struct sw_port *port;
	u32 qpn;

	qp->sq_sig_type		= init->sq_sig_type;
	qp->attr.path_mtu	= 1;
	qp->mtu			= ib_mtu_enum_to_int(qp->attr.path_mtu);

	qpn			= qp->pelem.index;
	port			= &sw->port;

	switch (init->qp_type) {
	case IB_QPT_SMI:
		qp->ibqp.qp_num		= 0;
		port->qp_smi_index	= qpn;
		qp->attr.port_num	= init->port_num;
		break;

	case IB_QPT_GSI:
		qp->ibqp.qp_num		= 1;
		port->qp_gsi_index	= qpn;
		qp->attr.port_num	= init->port_num;
		break;

	default:
		qp->ibqp.qp_num		= qpn;
		break;
	}

	INIT_LIST_HEAD(&qp->grp_list);

	skb_queue_head_init(&qp->send_pkts);

	spin_lock_init(&qp->grp_lock);
	spin_lock_init(&qp->state_lock);

	atomic_set(&qp->ssn, 0);
	atomic_set(&qp->skb_out, 0);
}

static int sw_qp_init_req(struct sw_dev *sw, struct sw_qp *qp,
			   struct ib_qp_init_attr *init, struct ib_udata *udata,
			   struct sw_create_qp_resp __user *uresp)
{
	int err;
	int wqe_size;

#ifdef HAVE_SOCK_NO_NET_PARAM
	err = sock_create_kern(AF_INET, SOCK_DGRAM, 0, &qp->sk);
#else
	err = sock_create_kern(&init_net, AF_INET, SOCK_DGRAM, 0, &qp->sk);
#endif
	if (err < 0)
		return err;
	qp->sk->sk->sk_user_data = qp;

	/* pick a source UDP port number for this QP based on
	 * the source QPN. this spreads traffic for different QPs
	 * across different NIC RX queues (while using a single
	 * flow for a given QP to maintain packet order).
	 * the port number must be in the Dynamic Ports range
	 * (0xc000 - 0xffff).
	 */
	qp->src_port = SW_ROCE_V2_SPORT +
		(hash_32(qp_num(qp), 14) & 0x3fff);
	qp->sq.max_wr		= init->cap.max_send_wr;

	/* These caps are limited by sw_qp_chk_cap() done by the caller */
	wqe_size = max_t(int, init->cap.max_send_sge * sizeof(struct ib_sge),
			 init->cap.max_inline_data);
	qp->sq.max_sge = init->cap.max_send_sge =
		wqe_size / sizeof(struct ib_sge);
	qp->sq.max_inline = init->cap.max_inline_data = wqe_size;
	wqe_size += sizeof(struct sw_send_wqe);

	qp->sq.queue = sw_queue_init(sw, &qp->sq.max_wr, wqe_size);
	if (!qp->sq.queue)
		return -ENOMEM;

	qp->req.wqe_index	= producer_index(qp->sq.queue);
	qp->req.state		= QP_STATE_RESET;
	qp->req.opcode		= -1;
	qp->comp.opcode		= -1;

	spin_lock_init(&qp->sq.sq_lock);
	skb_queue_head_init(&qp->req_pkts);

	sw_init_task(sw, &qp->req.task, qp,
		      sw_requester, "req");
	sw_init_task(sw, &qp->comp.task, qp,
		      sw_completer, "comp");

	qp->qp_timeout_jiffies = 0; /* Can't be set for UD/UC in modify_qp */
	if (init->qp_type == IB_QPT_RC) {
		timer_setup(&qp->rnr_nak_timer, rnr_nak_timer, 0);
		timer_setup(&qp->retrans_timer, retransmit_timer, 0);
	}
	return 0;
}

static int sw_qp_init_resp(struct sw_dev *sw, struct sw_qp *qp,
			    struct ib_qp_init_attr *init,
			    struct ib_udata *udata,
			    struct sw_create_qp_resp __user *uresp)
{
	int wqe_size;

	if (!qp->srq) {
		qp->rq.max_wr		= init->cap.max_recv_wr;
		qp->rq.max_sge		= init->cap.max_recv_sge;

		wqe_size = rcv_wqe_size(qp->rq.max_sge);

		pr_debug("qp#%d max_wr = %d, max_sge = %d, wqe_size = %d\n",
			 qp_num(qp), qp->rq.max_wr, qp->rq.max_sge, wqe_size);

		qp->rq.queue = sw_queue_init(sw,
					      &qp->rq.max_wr,
					      wqe_size);
		if (!qp->rq.queue)
			return -ENOMEM;
	}

	spin_lock_init(&qp->rq.producer_lock);
	spin_lock_init(&qp->rq.consumer_lock);

	skb_queue_head_init(&qp->resp_pkts);

	sw_init_task(sw, &qp->resp.task, qp,
		      sw_responder, "resp");

	qp->resp.opcode		= OPCODE_NONE;
	qp->resp.msn		= 0;
	qp->resp.state		= QP_STATE_RESET;

	return 0;
}

static int attach_sw_pd(struct erdma_pd *pd, struct sw_dev *sw)
{
	struct ib_mr *mr;
	int ret;

	pd->sw_pd = kzalloc(sizeof(*pd->sw_pd), GFP_KERNEL);
	if (!pd->sw_pd)
		return -ENOMEM;

	pd->sw_pd->ibpd.device = &sw->ib_dev;
	ret = sw_alloc_pd(&pd->sw_pd->ibpd, NULL);
	if (ret)
		goto out;

	mr = sw_get_dma_mr(&pd->sw_pd->ibpd, IB_ACCESS_LOCAL_WRITE);
	if (IS_ERR(mr))
		goto out;

	pd->sw_pd->ibpd.local_dma_lkey = mr->lkey;
	pd->sw_pd->internal_mr = mr;
	mr->device = &sw->ib_dev;
	mr->pd = &pd->sw_pd->ibpd;
	mr->uobject = NULL;
	mr->need_inval = false;

	return 0;
out:
	kfree(pd->sw_pd);
	pd->sw_pd = NULL;
	return ret;
}

static int dealloc_sw_mr(struct ib_mr *ibmr)
{
	struct sw_mem *mr = to_rmr(ibmr);

	mr->state = SW_MEM_STATE_ZOMBIE;
	sw_drop_ref(mr_pd(mr));
	sw_drop_index(mr);
	sw_drop_ref(mr);
	return 0;
}

void detach_sw_pd(struct erdma_pd *pd)
{
	dealloc_sw_mr(pd->sw_pd->internal_mr);
	sw_dealloc_pd(&pd->sw_pd->ibpd, NULL);
	kfree(pd->sw_pd);
	pd->sw_pd = NULL;
}

static int attach_sw_cq(struct erdma_cq *cq, struct sw_dev * sw)
{
	struct ib_cq_init_attr attr;
	int ret;

#ifdef HAVE_RDMA_RESTRACK_ENTRY_USER
	if (!rdma_is_kernel_res(&cq->ibcq.res)) {
#else
	if (cq->user) {
#endif
		return -EINVAL;
	}

	cq->sw_cq = kzalloc(sizeof(*cq->sw_cq), GFP_KERNEL);
	if (!cq->sw_cq)
		return -ENOMEM;

	cq->sw_cq->ibcq.device = &sw->ib_dev;
	attr.cqe = cq->ibcq.cqe;
	attr.comp_vector = cq->assoc_eqn - 1;
	attr.flags = 0;

	ret = sw_create_cq(&cq->sw_cq->ibcq, &attr, NULL);
	if (ret)
		goto free_scq;

	memcpy(&cq->sw_cq->ibcq, &cq->ibcq, sizeof(cq->ibcq));

	return 0;

free_scq:
	kfree(cq->sw_cq);
	cq->sw_cq = NULL;
	return ret;
}

void detach_sw_cq(struct erdma_cq *cq)
{
	sw_destroy_cq(&cq->sw_cq->ibcq, NULL);
	kfree(cq->sw_cq);
	cq->sw_cq = NULL;
}

int create_sw_qp_components(struct sw_qp *sw_qp, struct ib_pd *ibpd, struct sw_dev *sw)
{
	struct erdma_qp *qp = sw_qp->master;
	int ret;

	ret = attach_sw_pd(to_epd(ibpd), sw);
	if (ret)
		return ret;

	ret = attach_sw_cq(qp->scq, sw);
	if (ret)
		goto free_pd;

	if (qp->scq != qp->rcq) {
		ret = attach_sw_cq(qp->rcq, sw);
		if (ret)
			goto free_scq;
	}
	return 0;

free_scq:
	detach_sw_cq(qp->scq);
free_pd:
	detach_sw_pd(to_epd(ibpd));
	return ret;
}

void destroy_sw_qp_components(struct sw_qp *sw_qp, struct ib_pd *ibpd)
{
	struct erdma_qp *qp = sw_qp->master;

	detach_sw_cq(qp->scq);
	detach_sw_pd(to_epd(ibpd));
}

/* called by the create qp verb */
int sw_qp_from_init(struct sw_dev *sw, struct sw_qp *qp,
		     struct ib_qp_init_attr *init,
		     struct sw_create_qp_resp __user *uresp,
		     struct ib_pd *ibpd,
		     struct ib_udata *udata)
{
	struct erdma_cq *rcq = to_ecq(init->recv_cq);
	struct erdma_cq *scq = to_ecq(init->send_cq);
	struct erdma_pd *pd = to_epd(ibpd);
	int err;

	if (init->srq)
		return -EINVAL;

	qp->master->scq = to_ecq(init->send_cq);
	qp->master->rcq = to_ecq(init->recv_cq);
	qp->master->dev = container_of(sw, struct erdma_dev, sw_dev);

	err = create_sw_qp_components(qp, ibpd, sw);
	if (err)
		return err;

	sw_add_ref(pd->sw_pd);
	sw_add_ref(rcq->sw_cq);
	sw_add_ref(scq->sw_cq);

	qp->pd			= pd->sw_pd;
	qp->rcq			= rcq->sw_cq;
	qp->scq			= scq->sw_cq;
	qp->srq			= NULL;

	rcq->sw_cq->ibcq.device = &sw->ib_dev;
	scq->sw_cq->ibcq.device = &sw->ib_dev;
	scq->sw_cq->ibcq.comp_handler = scq->ibcq.comp_handler;
	rcq->sw_cq->ibcq.comp_handler = rcq->ibcq.comp_handler;
	scq->sw_cq->ibcq.event_handler = scq->ibcq.event_handler;
	rcq->sw_cq->ibcq.event_handler = rcq->ibcq.event_handler;
	scq->sw_cq->ibcq.cq_context = scq->ibcq.cq_context;
	rcq->sw_cq->ibcq.cq_context = rcq->ibcq.cq_context;
	scq->sw_cq->master = scq;
	rcq->sw_cq->master = rcq;

	sw_qp_init_misc(sw, qp, init);

	err = sw_qp_init_req(sw, qp, init, udata, uresp);
	if (err)
		goto err1;

	err = sw_qp_init_resp(sw, qp, init, udata, uresp);
	if (err)
		goto err2;

	qp->attr.qp_state = IB_QPS_RESET;
	qp->valid = 1;

	return 0;

err2:
	kernel_sock_shutdown(qp->sk, SHUT_RDWR);
	sock_release(qp->sk);
	sw_queue_cleanup(qp->sq.queue);
err1:
	qp->pd = NULL;
	qp->rcq = NULL;
	qp->scq = NULL;
	qp->srq = NULL;

	destroy_sw_qp_components(qp, ibpd);

	sw_drop_ref(pd->sw_pd);
	sw_drop_ref(rcq->sw_cq);
	sw_drop_ref(scq->sw_cq);

	return err;
}

/* called by the query qp verb */
int sw_qp_to_init(struct sw_qp *qp, struct ib_qp_init_attr *init)
{
	init->event_handler		= qp->ibqp.event_handler;
	init->qp_context		= qp->ibqp.qp_context;
	init->send_cq			= qp->ibqp.send_cq;
	init->recv_cq			= qp->ibqp.recv_cq;
	init->srq			= qp->ibqp.srq;

	init->cap.max_send_wr		= qp->sq.max_wr;
	init->cap.max_send_sge		= qp->sq.max_sge;
	init->cap.max_inline_data	= qp->sq.max_inline;

	if (!qp->srq) {
		init->cap.max_recv_wr		= qp->rq.max_wr;
		init->cap.max_recv_sge		= qp->rq.max_sge;
	}

	init->sq_sig_type		= qp->sq_sig_type;

	init->qp_type			= qp->ibqp.qp_type;
	init->port_num			= 1;

	return 0;
}

/* called by the modify qp verb, this routine checks all the parameters before
 * making any changes
 */
int sw_qp_chk_attr(struct sw_dev *sw, struct sw_qp *qp,
		    struct ib_qp_attr *attr, int mask)
{
	enum ib_qp_state cur_state = (mask & IB_QP_CUR_STATE) ?
					attr->cur_qp_state : qp->attr.qp_state;
	enum ib_qp_state new_state = (mask & IB_QP_STATE) ?
					attr->qp_state : cur_state;

	//if (!ib_modify_qp_is_ok(cur_state, new_state, qp_type(qp), mask)) {
	//	pr_warn("invalid mask or state for qp\n");
	//	goto err1;
	//}

	if (mask & IB_QP_STATE) {
		if (cur_state == IB_QPS_SQD) {
			if (qp->req.state == QP_STATE_DRAIN &&
			    new_state != IB_QPS_ERR)
				goto err1;
		}
	}

	if (mask & IB_QP_PORT) {
		if (!rdma_is_port_valid(&sw->ib_dev, attr->port_num)) {
			pr_warn("invalid port %d\n", attr->port_num);
			goto err1;
		}
	}

	if (mask & IB_QP_CAP && sw_qp_chk_cap(sw, &attr->cap, !!qp->srq))
		goto err1;

	if (mask & IB_QP_AV && sw_av_chk_attr(sw, &attr->ah_attr))
		goto err1;

	if (mask & IB_QP_ALT_PATH) {
		if (sw_av_chk_attr(sw, &attr->alt_ah_attr))
			goto err1;
		if (!rdma_is_port_valid(&sw->ib_dev, attr->alt_port_num))  {
			pr_warn("invalid alt port %d\n", attr->alt_port_num);
			goto err1;
		}
		if (attr->alt_timeout > 31) {
			pr_warn("invalid QP alt timeout %d > 31\n",
				attr->alt_timeout);
			goto err1;
		}
	}

	if (mask & IB_QP_PATH_MTU) {
		struct sw_port *port = &sw->port;

		enum ib_mtu max_mtu = port->attr.max_mtu;
		enum ib_mtu mtu = attr->path_mtu;

		if (mtu > max_mtu) {
			pr_debug("invalid mtu (%d) > (%d)\n",
				 ib_mtu_enum_to_int(mtu),
				 ib_mtu_enum_to_int(max_mtu));
			goto err1;
		}
	}

	if (mask & IB_QP_MAX_QP_RD_ATOMIC) {
		if (attr->max_rd_atomic > sw->attr.max_qp_rd_atom) {
			pr_warn("invalid max_rd_atomic %d > %d\n",
				attr->max_rd_atomic,
				sw->attr.max_qp_rd_atom);
			goto err1;
		}
	}

	if (mask & IB_QP_TIMEOUT) {
		if (attr->timeout > 31) {
			pr_warn("invalid QP timeout %d > 31\n",
				attr->timeout);
			goto err1;
		}
	}

	return 0;

err1:
	return -EINVAL;
}

/* move the qp to the reset state */
static void sw_qp_reset(struct sw_qp *qp)
{
	/* stop tasks from running */
	sw_disable_task(&qp->resp.task);

	/* stop request/comp */
	if (qp->sq.queue) {
		if (qp_type(qp) == IB_QPT_RC)
			sw_disable_task(&qp->comp.task);
		sw_disable_task(&qp->req.task);
	}

	/* move qp to the reset state */
	qp->req.state = QP_STATE_RESET;
	qp->resp.state = QP_STATE_RESET;

	/* let state machines reset themselves drain work and packet queues
	 * etc.
	 */
	__sw_do_task(&qp->resp.task);

	if (qp->sq.queue) {
		__sw_do_task(&qp->comp.task);
		__sw_do_task(&qp->req.task);
		sw_queue_reset(qp->sq.queue);
	}

	/* cleanup attributes */
	atomic_set(&qp->ssn, 0);
	qp->req.opcode = -1;
	qp->req.need_retry = 0;
	qp->req.noack_pkts = 0;
	qp->resp.msn = 0;
	qp->resp.opcode = -1;
	qp->resp.drop_msg = 0;
	qp->resp.goto_error = 0;
	qp->resp.sent_psn_nak = 0;

	if (qp->resp.mr) {
		sw_drop_ref(qp->resp.mr);
		qp->resp.mr = NULL;
	}

	cleanup_rd_atomic_resources(qp);

	/* reenable tasks */
	sw_enable_task(&qp->resp.task);

	if (qp->sq.queue) {
		if (qp_type(qp) == IB_QPT_RC)
			sw_enable_task(&qp->comp.task);

		sw_enable_task(&qp->req.task);
	}
}

/* drain the send queue */
static void sw_qp_drain(struct sw_qp *qp)
{
	if (qp->sq.queue) {
		if (qp->req.state != QP_STATE_DRAINED) {
			qp->req.state = QP_STATE_DRAIN;
			if (qp_type(qp) == IB_QPT_RC)
				sw_run_task(&qp->comp.task, 1);
			else
				__sw_do_task(&qp->comp.task);
			sw_run_task(&qp->req.task, 1);
		}
	}
}

/* move the qp to the error state */
void sw_qp_error(struct sw_qp *qp)
{
	qp->req.state = QP_STATE_ERROR;
	qp->resp.state = QP_STATE_ERROR;
	qp->attr.qp_state = IB_QPS_ERR;

	/* drain work and packet queues */
	dump_stack();
	sw_run_task(&qp->resp.task, 1);

	if (qp_type(qp) == IB_QPT_RC)
		sw_run_task(&qp->comp.task, 1);
	else
		__sw_do_task(&qp->comp.task);
	sw_run_task(&qp->req.task, 1);
}

/* called by the modify qp verb */
int sw_qp_from_attr(struct sw_qp *qp, struct ib_qp_attr *attr, int mask,
		     struct ib_udata *udata)
{
	int err;

	if (mask & IB_QP_MAX_QP_RD_ATOMIC) {
		int max_rd_atomic = attr->max_rd_atomic ?
			roundup_pow_of_two(attr->max_rd_atomic) : 0;

		qp->attr.max_rd_atomic = max_rd_atomic;
		atomic_set(&qp->req.rd_atomic, max_rd_atomic);
	}

	if (mask & IB_QP_MAX_DEST_RD_ATOMIC) {
		int max_dest_rd_atomic = attr->max_dest_rd_atomic ?
			roundup_pow_of_two(attr->max_dest_rd_atomic) : 0;

		qp->attr.max_dest_rd_atomic = max_dest_rd_atomic;

		free_rd_atomic_resources(qp);

		err = alloc_rd_atomic_resources(qp, max_dest_rd_atomic);
		if (err)
			return err;
	}

	if (mask & IB_QP_CUR_STATE)
		qp->attr.cur_qp_state = attr->qp_state;

	if (mask & IB_QP_EN_SQD_ASYNC_NOTIFY)
		qp->attr.en_sqd_async_notify = attr->en_sqd_async_notify;

	if (mask & IB_QP_ACCESS_FLAGS)
		qp->attr.qp_access_flags = attr->qp_access_flags;

	if (mask & IB_QP_PKEY_INDEX)
		qp->attr.pkey_index = attr->pkey_index;

	if (mask & IB_QP_PORT)
		qp->attr.port_num = attr->port_num;

	if (mask & IB_QP_QKEY)
		qp->attr.qkey = attr->qkey;

	if (mask & IB_QP_AV)
		sw_init_av(&attr->ah_attr, &qp->pri_av);

	if (mask & IB_QP_ALT_PATH) {
		sw_init_av(&attr->alt_ah_attr, &qp->alt_av);
		qp->attr.alt_port_num = attr->alt_port_num;
		qp->attr.alt_pkey_index = attr->alt_pkey_index;
		qp->attr.alt_timeout = attr->alt_timeout;
	}

	if (mask & IB_QP_PATH_MTU) {
		qp->attr.path_mtu = attr->path_mtu;
		qp->mtu = ib_mtu_enum_to_int(attr->path_mtu);
	}

	if (mask & IB_QP_TIMEOUT) {
		qp->attr.timeout = attr->timeout;
		if (attr->timeout == 0) {
			qp->qp_timeout_jiffies = 0;
		} else {
			/* According to the spec, timeout = 4.096 * 2 ^ attr->timeout [us] */
			int j = nsecs_to_jiffies(4096ULL << attr->timeout);

			qp->qp_timeout_jiffies = j ? j : 1;
		}
	}

	if (mask & IB_QP_RETRY_CNT) {
		qp->attr.retry_cnt = attr->retry_cnt;
		qp->comp.retry_cnt = attr->retry_cnt;
		pr_debug("qp#%d set retry count = %d\n", qp_num(qp),
			 attr->retry_cnt);
	}

	if (mask & IB_QP_RNR_RETRY) {
		qp->attr.rnr_retry = attr->rnr_retry;
		qp->comp.rnr_retry = attr->rnr_retry;
		pr_debug("qp#%d set rnr retry count = %d\n", qp_num(qp),
			 attr->rnr_retry);
	}

	if (mask & IB_QP_RQ_PSN) {
		qp->attr.rq_psn = (attr->rq_psn & BTH_PSN_MASK);
		qp->resp.psn = qp->attr.rq_psn;
		pr_debug("qp#%d set resp psn = 0x%x\n", qp_num(qp),
			 qp->resp.psn);
	}

	if (mask & IB_QP_MIN_RNR_TIMER) {
		qp->attr.min_rnr_timer = attr->min_rnr_timer;
		pr_debug("qp#%d set min rnr timer = 0x%x\n", qp_num(qp),
			 attr->min_rnr_timer);
	}

	if (mask & IB_QP_SQ_PSN) {
		qp->attr.sq_psn = (attr->sq_psn & BTH_PSN_MASK);
		qp->req.psn = qp->attr.sq_psn;
		qp->comp.psn = qp->attr.sq_psn;
		pr_debug("qp#%d set req psn = 0x%x\n", qp_num(qp), qp->req.psn);
	}

	if (mask & IB_QP_PATH_MIG_STATE)
		qp->attr.path_mig_state = attr->path_mig_state;

	if (mask & IB_QP_DEST_QPN)
		qp->attr.dest_qp_num = attr->dest_qp_num;

	if (mask & IB_QP_STATE) {
		qp->attr.qp_state = attr->qp_state;

		switch (attr->qp_state) {
		case IB_QPS_RESET:
			pr_debug("qp#%d state -> RESET\n", qp_num(qp));
			sw_qp_reset(qp);
			break;

		case IB_QPS_INIT:
			pr_debug("qp#%d state -> INIT\n", qp_num(qp));
			qp->req.state = QP_STATE_INIT;
			qp->resp.state = QP_STATE_INIT;
			break;

		case IB_QPS_RTR:
			pr_debug("qp#%d state -> RTR\n", qp_num(qp));
			qp->resp.state = QP_STATE_READY;
			break;

		case IB_QPS_RTS:
			pr_debug("qp#%d state -> RTS\n", qp_num(qp));
			qp->req.state = QP_STATE_READY;
			break;

		case IB_QPS_SQD:
			pr_debug("qp#%d state -> SQD\n", qp_num(qp));
			sw_qp_drain(qp);
			break;

		case IB_QPS_SQE:
			pr_warn("qp#%d state -> SQE !!?\n", qp_num(qp));
			/* Not possible from modify_qp. */
			break;

		case IB_QPS_ERR:
			pr_emerg("qp#%d state -> ERR\n", qp_num(qp));
			sw_qp_error(qp);
			break;
		}
	}

	return 0;
}

/* called by the query qp verb */
int sw_qp_to_attr(struct sw_qp *qp, struct ib_qp_attr *attr, int mask)
{
	*attr = qp->attr;

	attr->rq_psn				= qp->resp.psn;
	attr->sq_psn				= qp->req.psn;

	attr->cap.max_send_wr			= qp->sq.max_wr;
	attr->cap.max_send_sge			= qp->sq.max_sge;
	attr->cap.max_inline_data		= qp->sq.max_inline;

	if (!qp->srq) {
		attr->cap.max_recv_wr		= qp->rq.max_wr;
		attr->cap.max_recv_sge		= qp->rq.max_sge;
	}

	sw_av_to_attr(&qp->pri_av, &attr->ah_attr);
	sw_av_to_attr(&qp->alt_av, &attr->alt_ah_attr);

	if (qp->req.state == QP_STATE_DRAIN) {
		attr->sq_draining = 1;
		/* applications that get this state
		 * typically spin on it. yield the
		 * processor
		 */
		cond_resched();
	} else {
		attr->sq_draining = 0;
	}

	pr_debug("attr->sq_draining = %d\n", attr->sq_draining);

	return 0;
}

/* called by the destroy qp verb */
void sw_qp_destroy(struct sw_qp *qp)
{
	qp->valid = 0;
	qp->qp_timeout_jiffies = 0;
	sw_cleanup_task(&qp->resp.task);

	if (qp_type(qp) == IB_QPT_RC) {
		del_timer_sync(&qp->retrans_timer);
		del_timer_sync(&qp->rnr_nak_timer);
	}

	sw_cleanup_task(&qp->req.task);
	sw_cleanup_task(&qp->comp.task);

	/* flush out any receive wr's or pending requests */
	__sw_do_task(&qp->req.task);
	if (qp->sq.queue) {
		__sw_do_task(&qp->comp.task);
		__sw_do_task(&qp->req.task);
	}
}

void cleanup_sw_qp(struct sw_qp *qp)
{
	sw_drop_all_mcast_groups(qp);

	if (qp->sq.queue)
		sw_queue_cleanup(qp->sq.queue);

	if (qp->srq)
		sw_drop_ref(qp->srq);

	if (qp->rq.queue)
		sw_queue_cleanup(qp->rq.queue);

	if (qp->scq)
		sw_drop_ref(qp->scq);
	if (qp->rcq)
		sw_drop_ref(qp->rcq);
	if (qp->pd)
		sw_drop_ref(qp->pd);

	if (qp->resp.mr) {
		sw_drop_ref(qp->resp.mr);
		qp->resp.mr = NULL;
	}

	if (qp_type(qp) == IB_QPT_RC)
		sk_dst_reset(qp->sk->sk);

	free_rd_atomic_resources(qp);

	kernel_sock_shutdown(qp->sk, SHUT_RDWR);
	sock_release(qp->sk);
}

/* called when the last reference to the qp is dropped */
static void sw_qp_do_cleanup(struct work_struct *work)
{
	struct sw_qp *qp = container_of(work, typeof(*qp), cleanup_work.work);

	sw_drop_all_mcast_groups(qp);

	if (qp->sq.queue)
		sw_queue_cleanup(qp->sq.queue);

	if (qp->srq)
		sw_drop_ref(qp->srq);

	if (qp->rq.queue)
		sw_queue_cleanup(qp->rq.queue);

	if (qp->scq)
		sw_drop_ref(qp->scq);
	if (qp->rcq)
		sw_drop_ref(qp->rcq);
	if (qp->pd)
		sw_drop_ref(qp->pd);

	if (qp->resp.mr) {
		sw_drop_ref(qp->resp.mr);
		qp->resp.mr = NULL;
	}

	if (qp_type(qp) == IB_QPT_RC)
		sk_dst_reset(qp->sk->sk);

	free_rd_atomic_resources(qp);

	kernel_sock_shutdown(qp->sk, SHUT_RDWR);
	sock_release(qp->sk);
}

/* called when the last reference to the qp is dropped */
void sw_qp_cleanup(struct sw_pool_entry *arg)
{
	struct sw_qp *qp = container_of(arg, typeof(*qp), pelem);

	execute_in_process_context(sw_qp_do_cleanup, &qp->cleanup_work);
}
