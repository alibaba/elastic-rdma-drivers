/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
 * Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.
 */

#ifndef SW_LOC_H
#define SW_LOC_H

/* sw_av.c */
void sw_init_av(struct rdma_ah_attr *attr, struct sw_av *av);

int sw_av_chk_attr(struct sw_dev *sw, struct rdma_ah_attr *attr);

void sw_av_from_attr(u8 port_num, struct sw_av *av,
		     struct rdma_ah_attr *attr);

void sw_av_to_attr(struct sw_av *av, struct rdma_ah_attr *attr);

void sw_av_fill_ip_info(struct sw_av *av, struct rdma_ah_attr *attr);

struct sw_av *sw_get_av(struct sw_pkt_info *pkt);

/* sw_cq.c */
int sw_cq_chk_attr(struct sw_dev *sw, struct sw_cq *cq,
		    int cqe, int comp_vector);

int sw_cq_from_init(struct sw_dev *sw, struct sw_cq *cq, int cqe,
		     int comp_vector, struct ib_udata *udata,
		     struct sw_create_cq_resp __user *uresp);

int sw_cq_post(struct sw_cq *cq, struct sw_cqe *cqe, int solicited);

void sw_cq_disable(struct sw_cq *cq);

void sw_cq_cleanup(struct sw_pool_entry *arg);

/* sw_mcast.c */
int sw_mcast_get_grp(struct sw_dev *sw, union ib_gid *mgid,
		      struct sw_mc_grp **grp_p);

int sw_mcast_add_grp_elem(struct sw_dev *sw, struct sw_qp *qp,
			   struct sw_mc_grp *grp);

int sw_mcast_drop_grp_elem(struct sw_dev *sw, struct sw_qp *qp,
			    union ib_gid *mgid);

void sw_drop_all_mcast_groups(struct sw_qp *qp);

void sw_mc_cleanup(struct sw_pool_entry *arg);

/* sw_mmap.c */
struct sw_mmap_info {
	struct list_head	pending_mmaps;
	struct ib_ucontext	*context;
	struct kref		ref;
	void			*obj;

	struct mminfo info;
};

struct sw_mmap_info *sw_create_mmap_info(struct sw_dev *dev, u32 size,
					   struct ib_udata *udata, void *obj);

int sw_mmap(struct ib_ucontext *context, struct vm_area_struct *vma);

/* sw_mr.c */
enum copy_direction {
	to_mem_obj,
	from_mem_obj,
};

void sw_mem_init_dma(struct sw_pd *pd,
		      int access, struct sw_mem *mem);

int sw_mem_init_user(struct sw_pd *pd, u64 start,
		      u64 length, u64 iova, int access, struct ib_udata *udata,
		      struct sw_mem *mr);

int sw_mem_init_fast(struct sw_pd *pd,
		      int max_pages, struct sw_mem *mem);

int sw_mem_copy(struct sw_mem *mem, u64 iova, void *addr,
		 int length, enum copy_direction dir, u32 *crcp);

int copy_data(struct sw_pd *pd, int access,
	      struct sw_dma_info *dma, void *addr, int length,
	      enum copy_direction dir, u32 *crcp);

void *iova_to_vaddr(struct sw_mem *mem, u64 iova, int length);

enum lookup_type {
	lookup_local,
	lookup_remote,
};

struct sw_mem *lookup_mem(struct sw_pd *pd, int access, u32 key,
			   enum lookup_type type);

int mem_check_range(struct sw_mem *mem, u64 iova, size_t length);

void sw_mem_cleanup(struct sw_pool_entry *arg);

int advance_dma_data(struct sw_dma_info *dma, unsigned int length);

/* sw_net.c */
void sw_loopback(struct sk_buff *skb);
int sw_send(struct sw_pkt_info *pkt, struct sk_buff *skb);
struct sk_buff *sw_init_packet(struct sw_dev *sw, struct sw_av *av,
				int paylen, struct sw_pkt_info *pkt);
int sw_prepare(struct sw_pkt_info *pkt, struct sk_buff *skb, u32 *crc);
const char *sw_parent_name(struct sw_dev *sw, unsigned int port_num);
struct device *sw_dma_device(struct sw_dev *sw);
int sw_mcast_add(struct sw_dev *sw, union ib_gid *mgid);
int sw_mcast_delete(struct sw_dev *sw, union ib_gid *mgid);

/* sw_qp.c */
int sw_qp_chk_init(struct sw_dev *sw, struct ib_qp_init_attr *init);

int sw_qp_from_init(struct sw_dev *sw, struct sw_qp *qp,
		     struct ib_qp_init_attr *init,
		     struct sw_create_qp_resp __user *uresp,
		     struct ib_pd *ibpd, struct ib_udata *udata);

int sw_qp_to_init(struct sw_qp *qp, struct ib_qp_init_attr *init);

int sw_qp_chk_attr(struct sw_dev *sw, struct sw_qp *qp,
		    struct ib_qp_attr *attr, int mask);

int sw_qp_from_attr(struct sw_qp *qp, struct ib_qp_attr *attr,
		     int mask, struct ib_udata *udata);

int sw_qp_to_attr(struct sw_qp *qp, struct ib_qp_attr *attr, int mask);

void sw_qp_error(struct sw_qp *qp);

void sw_qp_destroy(struct sw_qp *qp);

void sw_qp_cleanup(struct sw_pool_entry *arg);
/* for erdma_sw */
void cleanup_sw_qp(struct sw_qp *qp);

static inline int qp_num(struct sw_qp *qp)
{
	return qp->ibqp.qp_num;
}

static inline enum ib_qp_type qp_type(struct sw_qp *qp)
{
	return qp->ibqp.qp_type;
}

static inline enum ib_qp_state qp_state(struct sw_qp *qp)
{
	return qp->attr.qp_state;
}

static inline int qp_mtu(struct sw_qp *qp)
{
	if (qp->ibqp.qp_type == IB_QPT_RC || qp->ibqp.qp_type == IB_QPT_UC)
		return qp->attr.path_mtu;
	else
		return IB_MTU_4096;
}

static inline int rcv_wqe_size(int max_sge)
{
	return sizeof(struct sw_recv_wqe) +
		max_sge * sizeof(struct ib_sge);
}

void free_rd_atomic_resource(struct sw_qp *qp, struct resp_res *res);

static inline void sw_advance_resp_resource(struct sw_qp *qp)
{
	qp->resp.res_head++;
	if (unlikely(qp->resp.res_head == qp->attr.max_dest_rd_atomic))
		qp->resp.res_head = 0;
}

void retransmit_timer(struct timer_list *t);
void rnr_nak_timer(struct timer_list *t);

/* sw_srq.c */
#define IB_SRQ_INIT_MASK (~IB_SRQ_LIMIT)

int sw_srq_chk_attr(struct sw_dev *sw, struct sw_srq *srq,
		     struct ib_srq_attr *attr, enum ib_srq_attr_mask mask);

int sw_srq_from_init(struct sw_dev *sw, struct sw_srq *srq,
		      struct ib_srq_init_attr *init, struct ib_udata *udata,
		      struct sw_create_srq_resp __user *uresp);

int sw_srq_from_attr(struct sw_dev *sw, struct sw_srq *srq,
		      struct ib_srq_attr *attr, enum ib_srq_attr_mask mask,
		      struct sw_modify_srq_cmd *ucmd, struct ib_udata *udata);

int sw_completer(void *arg);
int sw_requester(void *arg);
int sw_responder(void *arg);

u32 sw_icrc_hdr(struct sw_pkt_info *pkt, struct sk_buff *skb);

void sw_resp_queue_pkt(struct sw_qp *qp, struct sk_buff *skb);

void sw_comp_queue_pkt(struct sw_qp *qp, struct sk_buff *skb);

static inline unsigned int wr_opcode_mask(int opcode, struct sw_qp *qp)
{
	return sw_wr_opcode_info[opcode].mask[qp->ibqp.qp_type];
}

static inline int sw_xmit_packet(struct sw_qp *qp, struct sw_pkt_info *pkt,
				  struct sk_buff *skb)
{
	int err;
	int is_request = pkt->mask & SW_REQ_MASK;
	struct sw_dev *sw = to_rdev(qp->ibqp.device);

	if ((is_request && (qp->req.state != QP_STATE_READY)) ||
	    (!is_request && (qp->resp.state != QP_STATE_READY))) {
		pr_info("Packet dropped. QP is not in ready state\n");
		goto drop;
	}

	if (pkt->mask & SW_LOOPBACK_MASK) {
		memcpy(SKB_TO_PKT(skb), pkt, sizeof(*pkt));
		sw_loopback(skb);
		err = 0;
	} else {
		err = sw_send(pkt, skb);
	}

	if (err) {
		sw->xmit_errors++;
		sw_counter_inc(sw, SW_CNT_SEND_ERR);
		return err;
	}

	if ((qp_type(qp) != IB_QPT_RC) &&
	    (pkt->mask & SW_END_MASK)) {
		pkt->wqe->state = wqe_state_done;
		sw_run_task(&qp->comp.task, 1);
	}

	sw_counter_inc(sw, SW_CNT_SENT_PKTS);
	goto done;

drop:
	kfree_skb(skb);
	err = 0;
done:
	return err;
}

#endif /* SW_LOC_H */
