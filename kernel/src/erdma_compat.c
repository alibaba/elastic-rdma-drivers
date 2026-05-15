#include <linux/dma-mapping.h>
#include <linux/module.h>
#include <net/addrconf.h>
#include <rdma/ib_addr.h>
#include <rdma/ib_cache.h>
#include <rdma/ib_mad.h>
#include <rdma/uverbs_ioctl.h>

#include "erdma-abi.h"
#include "erdma_verbs.h"

#include <linux/netdevice.h>
#include <net/netns/generic.h>

struct erdma_net {
	struct list_head erdma_list;
	struct socket *rsvd_sock[16];
	struct sw_recv_sockets mad_sock;
};

static unsigned int erdma_net_id;

#ifdef ENABLE_COMPAT_MODE
bool compat_mode = true;
#else
bool compat_mode;
#endif
module_param(compat_mode, bool, 0444);
MODULE_PARM_DESC(compat_mode, "compat mode support");

#ifdef HAVE_LEGACY_MODE_BY_DEFAULT
bool legacy_mode = true;
#else
bool legacy_mode;
#endif
module_param(legacy_mode, bool, 0444);
MODULE_PARM_DESC(legacy_mode, "legacy mode support");

u16 reserve_ports_base = 0x7790;
module_param(reserve_ports_base, ushort, 0444);
MODULE_PARM_DESC(reserve_ports_base, "ports reserved in compat mode");

#ifndef HAVE_SET_NON_SK_BOUND_IF
bool use_zeronet;
module_param(use_zeronet, bool, 0444);
MODULE_PARM_DESC(use_zeronet, "can use zeronet");
#endif

static unsigned int port_select_rule = 0;
module_param(port_select_rule, uint, 0644);
MODULE_PARM_DESC(port_select_rule,
		 "0: IP & QPN involved; 1: Only QPN involved");

#include "compat/sw.h"
#include "compat/sw_loc.h"
#include "compat/sw_queue.h"
#include "compat/sw_hw_counters.h"

static void erdma_alloc_gsi_mr_idx(struct ib_qp *ibqp)
{
	struct erdma_dev *dev = to_edev(ibqp->device);
	struct erdma_pd *pd = to_epd(ibqp->pd);
	struct sw_mem *sw_mr = to_rmr(pd->sw_pd->internal_mr);
	struct erdma_resource_cb *res_cb =
		&dev->res_cb[ERDMA_RES_TYPE_STAG_IDX];
	unsigned long flags;
	u32 idx;

	spin_lock_irqsave(&res_cb->lock, flags);
	idx = sw_mr->pelem.index - sw_mr->pelem.pool->min_index;
	set_bit(idx, res_cb->bitmap);
	spin_unlock_irqrestore(&res_cb->lock, flags);
}

int erdma_create_ud_qp(struct ib_qp *ibqp, struct ib_qp_init_attr *init,
		       struct ib_udata *udata)
{
	struct erdma_dev *dev = to_edev(ibqp->device);
	struct erdma_cq *scq = to_ecq(init->send_cq);
	struct erdma_cq *rcq = to_ecq(init->recv_cq);
	struct erdma_qp *qp = to_eqp(ibqp);
	struct erdma_uresp_create_qp uresp;
	struct sw_dev *sw = &dev->sw_dev;
	struct erdma_ucontext *uctx;
	struct sw_qp *sw_qp;
	int err;

	err = sw_qp_chk_init(sw, init);
	if (err)
		goto err1;

	sw_qp = kzalloc(sizeof(*sw_qp), GFP_KERNEL);
	if (!qp) {
		err = -ENOMEM;
		goto err1;
	}

#ifdef HAVE_UDATA_TO_DRV_CONTEXT
	uctx = rdma_udata_to_drv_context(udata, struct erdma_ucontext,
					 ibucontext);
#else
	uctx = ibqp->pd->uobject ? to_ectx(ibqp->pd->uobject->context) : NULL;
#endif

	kref_init(&sw_qp->pelem.ref_cnt);
	memcpy(&sw_qp->ibqp, &qp->ibqp, sizeof(qp->ibqp));

	scq->is_soft = true;
	rcq->is_soft = true;
	qp->sw_qp = sw_qp;
	sw_qp->master = qp;
	sw_qp->ibqp.device = &sw->ib_dev;

	err = sw_qp_from_init(sw, sw_qp, init, NULL, qp->ibqp.pd, udata,
			      &uctx->ibucontext);
	if (err)
		goto err2;

	/* Currently, GSI is created from kernel space.
	 * We will create a local_dma_mr for the GSI in the sw
	 * domain. We should set corresponding resource index in
	 * erdma domain in case that someone tries to allocate
	 * the used index when it calls erdma_reg_user_mr.
	 */
	if (init->qp_type == IB_QPT_GSI)
		erdma_alloc_gsi_mr_idx(ibqp);

	qp->attrs.max_send_sge = init->cap.max_send_sge;
	qp->attrs.max_recv_sge = init->cap.max_recv_sge;

	if (udata) {
		memset(&uresp, 0, sizeof(uresp));
		uresp.qp_id = QP_ID(qp);

		err = ib_copy_to_udata(udata, &uresp, sizeof(uresp));
		if (err)
			goto err2;
	}

	return 0;

err2:
	kfree(sw_qp);
err1:
	return err;
}

void erdma_destroy_mad_qp(struct ib_qp *ibqp)
{
	struct erdma_qp *qp = to_eqp(ibqp);

	sw_qp_destroy(qp->sw_qp);
	cleanup_sw_qp(qp->sw_qp);
	kfree(qp->sw_qp);
}

int erdma_modify_mad_qp(struct ib_qp *ibqp, struct ib_qp_attr *attr,
			int attr_mask, struct ib_udata *udata)
{
	struct erdma_qp *qp = to_eqp(ibqp);
	int ret;

	ret = sw_modify_qp(&qp->sw_qp->ibqp, attr, attr_mask, udata);
	return ret;
}

#ifdef HAVE_POST_CONST_WR
int erdma_post_send_mad(struct ib_qp *ibqp, const struct ib_send_wr *send_wr,
			const struct ib_send_wr **bad_send_wr)
#else
int erdma_post_send_mad(struct ib_qp *ibqp, struct ib_send_wr *send_wr,
			struct ib_send_wr **bad_send_wr)
#endif
{
	struct erdma_qp *qp = to_eqp(ibqp);

	return sw_post_send(&qp->sw_qp->ibqp, send_wr, bad_send_wr);
}

#ifdef HAVE_POST_CONST_WR
int erdma_post_recv_mad(struct ib_qp *ibqp, const struct ib_recv_wr *recv_wr,
			const struct ib_recv_wr **bad_recv_wr)
#else
int erdma_post_recv_mad(struct ib_qp *ibqp, struct ib_recv_wr *recv_wr,
			struct ib_recv_wr **bad_recv_wr)
#endif
{
	struct erdma_qp *qp = to_eqp(ibqp);

	return sw_post_recv(&qp->sw_qp->ibqp, recv_wr, bad_recv_wr);
}

int erdma_mad_poll_cq(struct ib_cq *ibcq, int num_entries, struct ib_wc *wc)
{
	struct erdma_cq *cq = to_ecq(ibcq);
	unsigned long flags;
	int ret;

	spin_lock_irqsave(&cq->kern_cq.lock, flags);
	ret = sw_poll_cq(&cq->sw_cq->ibcq, num_entries, wc);
	spin_unlock_irqrestore(&cq->kern_cq.lock, flags);

	return ret;
}

int erdma_mad_req_notify_cq(struct ib_cq *ibcq, enum ib_cq_notify_flags flags)
{
	struct erdma_cq *cq = to_ecq(ibcq);
	return sw_req_notify_cq(&cq->sw_cq->ibcq, flags);
}

int attach_sw_dev(struct erdma_dev *dev)
{
	struct sw_dev *sw = &dev->sw_dev;
	struct crypto_shash *tfm;
	int err;

	if (!compat_mode)
		return 0;

	dev->sw_dev.master = dev;
	dev->sw_dev.ndev = dev->netdev;

	err = sw_init(sw);
	if (err)
		return err;

	sw_set_mtu(sw, dev->netdev->mtu);

	tfm = crypto_alloc_shash("crc32", 0, 0);
	if (IS_ERR(tfm)) {
		sw_dealloc(sw);
		pr_err("failed to allocate crc algorithm err:%ld\n",
		       PTR_ERR(tfm));
		return PTR_ERR(tfm);
	}
	sw->tfm = tfm;

#ifdef HAVE_DEV_PARENT
	sw->ib_dev.dma_device = dev->ibdev.dev.parent;
#else
	sw->ib_dev.dma_device = dev->ibdev.dma_device;
#endif

	return 0;
}

void detach_sw_dev(struct erdma_dev *dev)
{
	if (!compat_mode)
		return;

	sw_dealloc(&dev->sw_dev);
}

int attach_sw_mr(struct erdma_pd *pd, struct erdma_mr *emr,
		 struct ib_udata *udata, struct ib_ucontext *uctx)
{
	struct sw_dev *sw = to_rdev(pd->sw_pd->ibpd.device);
	struct ib_mr *ibmr;
	struct sw_mem *mr;

	if (emr->sw_mr)
		return 0;

	ibmr = sw_reg_user_mr(&pd->sw_pd->ibpd, emr->mem.start, emr->mem.len,
			      emr->mem.va, to_ib_access_flags(emr->access),
			      udata, uctx, emr->ibmr.lkey);
	if (IS_ERR(ibmr))
		return PTR_ERR(ibmr);

	mr = to_rmr(ibmr);
	ibmr->device = &sw->ib_dev;
	ibmr->lkey = emr->ibmr.lkey;
	ibmr->rkey = emr->ibmr.rkey;
	ibmr->uobject = emr->ibmr.uobject;
	emr->sw_mr = mr;

	return 0;
}

void detach_sw_mr(struct erdma_mr *emr, struct ib_udata *udata)
{
	sw_dereg_mr(&emr->sw_mr->ibmr, udata);
	emr->sw_mr = NULL;
}

int erdma_create_ah(struct ib_ah *ibah,
#ifdef HAVE_CREATE_AH_RDMA_INIT_ATTR
		    struct rdma_ah_init_attr *init_attr,
#else
		    struct rdma_ah_attr *ah_attr, u32 flags,
#endif
		    struct ib_udata *udata)
{
	if (!compat_mode)
		return -EOPNOTSUPP;

#ifdef HAVE_CREATE_AH_RDMA_INIT_ATTR
	return sw_create_ah(ibah, init_attr->ah_attr, udata);
#else
	return sw_create_ah(ibah, ah_attr, udata);
#endif
}

#ifndef HAVE_AH_CORE_ALLOCATION
#ifdef HAVE_CREATE_AH_FLAGS
struct ib_ah *erdma_kzalloc_ah(struct ib_pd *ibpd, struct rdma_ah_attr *ah_attr,
			       u32 flags, struct ib_udata *udata)
#elif defined(HAVE_CREATE_AH_RDMA_ATTR)
struct ib_ah *erdma_kzalloc_ah(struct ib_pd *ibpd, struct rdma_ah_attr *ah_attr,
			       struct ib_udata *udata)
#else
struct ib_ah *erdma_kzalloc_ah(struct ib_pd *ibpd, struct ib_ah_attr *ah_attr)
#endif
{
	struct sw_pd *pd = to_rpd(ibpd);
	struct sw_ah *ah;
	int ret;

	if (!compat_mode)
		return ERR_PTR(-EOPNOTSUPP);

	ah = kzalloc(sizeof(*ah), GFP_KERNEL);
	if (!ah)
		return ERR_PTR(-ENOMEM);

	ah->pd = pd;
	ah->ibah.device = ibpd->device;
	ah->ibah.pd = ibpd;

#ifdef HAVE_CREATE_AH_FLAGS
	ret = erdma_create_ah(&ah->ibah, ah_attr, flags, udata);
#elif defined(HAVE_CREATE_AH_RDMA_ATTR)
	ret = erdma_create_ah(&ah->ibah, ah_attr, 0, udata);
#else
	ret = -EOPNOTSUPP;
#endif
	if (ret)
		goto out_free;

	return &ah->ibah;

out_free:
	kfree(ah);
	return ERR_PTR(ret);
}
#endif

#ifdef HAVE_AH_CORE_ALLOCATION_DESTROY_RC
int erdma_destroy_ah(struct ib_ah *ibah, u32 flags)
#elif defined(HAVE_AH_CORE_ALLOCATION) && defined(HAVE_DESTROY_AH_VOID)
void erdma_destroy_ah(struct ib_ah *ibah, u32 flags)
#elif defined(HAVE_DESTROY_AH_FLAGS)
int erdma_destroy_ah(struct ib_ah *ibah, u32 flags)
#else
int erdma_destroy_ah(struct ib_ah *ibah)
#endif
{
	struct sw_ah *ah = to_rah(ibah);

	if (!compat_mode)
#if defined(HAVE_AH_CORE_ALLOCATION) && defined(HAVE_DESTROY_AH_VOID) && \
	!defined(HAVE_AH_CORE_ALLOCATION_DESTROY_RC)
		return;
#else
		return -EOPNOTSUPP;
#endif

	sw_drop_ref(ah);

#if defined(HAVE_AH_CORE_ALLOCATION) && defined(HAVE_DESTROY_AH_VOID) && \
	!defined(HAVE_AH_CORE_ALLOCATION_DESTROY_RC)
	return;
#else
	return 0;
#endif
}

int erdma_query_pkey(struct ib_device *ibdev, port_t port, u16 index, u16 *pkey)
{
	if (index > 0)
		return -EINVAL;

	*pkey = 0xffff;
	return 0;
}

enum rdma_link_layer erdma_get_link_layer(struct ib_device *dev,
					  port_t port_num)
{
	return IB_LINK_LAYER_ETHERNET;
}

#ifdef HAVE_OLD_GID_OPERATION
int erdma_add_gid(const struct ib_gid_attr *attr, void **context)
#else
int erdma_add_gid(struct ib_device *device, u8 port_num, unsigned int index,
		  const union ib_gid *gid, const struct ib_gid_attr *attr,
		  void **context)
#endif
{
	return 0;
}

#ifdef HAVE_OLD_GID_OPERATION
int erdma_del_gid(const struct ib_gid_attr *attr, void **context)
#else
int erdma_del_gid(struct ib_device *device, u8 port_num, unsigned int index,
		  void **context)
#endif
{
	return 0;
}

void erdma_gen_port_from_qpn(u32 sip, u32 dip, u32 lqpn, u32 rqpn, u16 *sport,
			     u16 *dport)
{
	/* select lqpn 0, select rqpn 1 */
	u32 select_type = 1;

	if (!port_select_rule) {
		if (dip < sip || (dip == sip && lqpn < rqpn))
			select_type = 0;
	} else {
		if (lqpn < rqpn)
			select_type = 0;
	}

	if (select_type) {
		*sport = reserve_ports_base + upper_16_bits(rqpn);
		*dport = lower_16_bits(rqpn);
	} else {
		*dport = reserve_ports_base + upper_16_bits(lqpn);
		*sport = lower_16_bits(lqpn);
	}
}

static int erdma_av_from_attr(struct erdma_qp *qp, struct ib_qp_attr *attr)
{
#ifdef HAVE_CREATE_AH_RDMA_ATTR
	struct rdma_ah_attr *ah_attr = &attr->ah_attr;
#ifdef HAVE_IB_GLOBAL_ROUTE_WITH_SGID_ATTR
	const struct ib_gid_attr *sgid_attr = ah_attr->grh.sgid_attr;
#else
	struct ib_gid_attr sgid_attr;
	int err;
#endif
	int ntype;
	union ib_gid sgid;

	if (ah_attr->type != RDMA_AH_ATTR_TYPE_ROCE) {
		ibdev_dbg(&qp->dev->ibdev, "unsupport ah_attr type %u.\n",
			  ah_attr->type);
		return -ENOTSUPP;
	}

#ifdef HAVE_IB_GLOBAL_ROUTE_WITH_SGID_ATTR
	ntype = rdma_gid_attr_network_type(sgid_attr);
	sgid = sgid_attr->gid;
#else
	err = ib_get_sgid_attr(&qp->dev->ibdev, ah_attr, &sgid, &sgid_attr,
			       &ntype);
	if (err)
		return err;
#endif

	ibdev_dbg(&qp->dev->ibdev, "gid type:%d, sgid: %pI6\n", ntype,
		  sgid.raw);

	rdma_gid2ip((struct sockaddr *)&qp->attrs.laddr, &sgid);
	rdma_gid2ip((struct sockaddr *)&qp->attrs.raddr,
		    &rdma_ah_read_grh(ah_attr)->dgid);

	if (qp->attrs.laddr.in6.sin6_family == AF_INET6 &&
	    ipv6_addr_type(&qp->attrs.laddr.in6.sin6_addr) &
		    IPV6_ADDR_LINKLOCAL)
		return -EINVAL;

	if (qp->attrs.raddr.in6.sin6_family == AF_INET6 &&
	    ipv6_addr_type(&qp->attrs.raddr.in6.sin6_addr) &
		    IPV6_ADDR_LINKLOCAL)
		return -EINVAL;

	ibdev_dbg(&qp->dev->ibdev, "dgid: %pI6\n",
		  rdma_ah_read_grh(ah_attr)->dgid.raw);

	ibdev_dbg(&qp->dev->ibdev, "laddr:0x%x\n",
		  ntohl(qp->attrs.laddr.in.sin_addr.s_addr));
	ibdev_dbg(&qp->dev->ibdev, "raddr:0x%x\n",
		  ntohl(qp->attrs.raddr.in.sin_addr.s_addr));
#endif
	return 0;
}

int erdma_handle_compat_attr(struct erdma_qp *qp, struct ib_qp_attr *attr,
			     int attr_mask)
{
	int ret;

	ibdev_dbg(&qp->dev->ibdev, "attr mask: %x, av: %d, state:%d\n",
		  attr_mask, attr_mask & IB_QP_AV, attr_mask & IB_QP_STATE);

	if (attr_mask & IB_QP_AV) {
		ret = erdma_av_from_attr(qp, attr);
		if (ret)
			return ret;
	}

	if (attr_mask & IB_QP_DEST_QPN) {
		ibdev_dbg(&qp->dev->ibdev, "get remote qpn %u\n",
			  attr->dest_qp_num);
		qp->attrs.remote_qp_num = attr->dest_qp_num;
	}

	if (attr_mask & IB_QP_SQ_PSN) {
		ibdev_dbg(&qp->dev->ibdev, "get sqsn:%u\n", attr->sq_psn);
		qp->attrs.sq_psn = attr->sq_psn;
	}

	if (attr_mask & IB_QP_RQ_PSN) {
		ibdev_dbg(&qp->dev->ibdev, "get rqsn:%u\n", attr->rq_psn);
		qp->attrs.rq_psn = attr->rq_psn;
	}

	return 0;
}

static int erdma_port_init(struct net *net, struct socket **rsvd_sock)
{
	struct sockaddr_in laddr;
	int ret = 0, i, j;

	for (i = 0; i < 16; i++) {
		ret = __sock_create(net, AF_INET, SOCK_STREAM, IPPROTO_TCP,
				    &rsvd_sock[i], 1);
		if (ret < 0)
			goto err_out;
		memset(&laddr, 0, sizeof(struct sockaddr_in));
		laddr.sin_port = htons(reserve_ports_base + i);
		ret = rsvd_sock[i]->ops->bind(rsvd_sock[i],
					      (struct sockaddr *)&laddr,
					      sizeof(struct sockaddr_in));
		if (ret) {
			sock_release(rsvd_sock[i]);
			goto err_out;
		}
	}

	return 0;

err_out:
	for (j = 0; j < i; j++) {
		sock_release(rsvd_sock[j]);
		rsvd_sock[j] = NULL;
	}

	return ret;
}

static void erdma_port_release(struct socket **rsvd_sock)
{
	int i;

	if (!compat_mode)
		return;

	for (i = 0; i < 16; i++)
		if (rsvd_sock[i])
			sock_release(rsvd_sock[i]);
}

static __net_init int erdma_init_net(struct net *net)
{
	struct erdma_net *node = net_generic(net, erdma_net_id);
	int ret;

	ret = erdma_port_init(net, node->rsvd_sock);
	if (ret) {
		pr_err_ratelimited(
			"erdma_port_init failed for erdma_net(%u), ret = %d",
			erdma_net_id, ret);
		return ret;
	}

	ret = sw_net_init(&node->mad_sock, net);
	if (ret) {
		pr_err_ratelimited(
			"sw_net_init failed for erdma_net(%u), ret = %d",
			erdma_net_id, ret);
		erdma_port_release(node->rsvd_sock);
		return ret;
	}

	return 0;
}

static void __net_exit erdma_exit_batch_net(struct list_head *net_list)
{
	struct net *net;
	LIST_HEAD(list);

	rtnl_lock();
	list_for_each_entry(net, net_list, exit_list) {
		struct erdma_net *node = net_generic(net, erdma_net_id);
		erdma_port_release(node->rsvd_sock);
		sw_net_exit(&node->mad_sock);
	}
	rtnl_unlock();
}

static struct pernet_operations erdma_net_ops = {
	.init = erdma_init_net,
	.exit_batch = erdma_exit_batch_net,
	.id = &erdma_net_id,
	.size = sizeof(struct erdma_net),
};

int erdma_compat_init(void)
{
	if (!compat_mode)
		return 0;

	return register_pernet_subsys(&erdma_net_ops);
}

void erdma_compat_exit(void)
{
	if (!compat_mode)
		return;

	unregister_pernet_subsys(&erdma_net_ops);
}
