#include <linux/dma-mapping.h>
#include <linux/module.h>
#include <net/addrconf.h>
#include <rdma/ib_addr.h>
#include <rdma/ib_cache.h>
#include <rdma/ib_mad.h>
#include <rdma/uverbs_ioctl.h>

#include "erdma_verbs.h"

#include <linux/netdevice.h>
#include <net/netns/generic.h>

struct erdma_net {
       struct list_head erdma_list;
       struct socket *rsvd_sock[16];
};

static unsigned int erdma_net_id;

#ifdef HAVE_ERDMA_MAD
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

#ifdef HAVE_ERDMA_MAD
#include "compat/sw.h"
#include "compat/sw_loc.h"
#include "compat/sw_queue.h"
#include "compat/sw_hw_counters.h"

int erdma_create_mad_qp(struct ib_qp *ibqp, struct ib_qp_init_attr *init,
			struct ib_udata *udata)
{
	struct erdma_dev *dev = to_edev(ibqp->device);
	struct erdma_cq *scq = to_ecq(init->send_cq);
	struct erdma_cq *rcq = to_ecq(init->recv_cq);
	struct erdma_qp *qp = to_eqp(ibqp);
	struct sw_dev *sw = &dev->sw_dev;
	struct sw_qp *sw_qp;
	int err;

	if (udata)
		return -EINVAL;

	err = sw_qp_chk_init(sw, init);
	if (err)
		goto err1;

	sw_qp = kzalloc(sizeof(*sw_qp), GFP_KERNEL);
	if (!qp) {
		err = -ENOMEM;
		goto err1;
	}
	kref_init(&sw_qp->pelem.ref_cnt);
	memcpy(&sw_qp->ibqp, &qp->ibqp, sizeof(qp->ibqp));

	scq->is_soft = true;
	rcq->is_soft = true;
	qp->sw_qp = sw_qp;
	sw_qp->master = qp;
	sw_qp->ibqp.device = &sw->ib_dev;

	err = sw_qp_from_init(sw, sw_qp, init, NULL, qp->ibqp.pd, NULL);
	if (err)
		goto err2;

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

	return 0;
}

void detach_sw_dev(struct erdma_dev *dev)
{
	if (!compat_mode)
		return;

	sw_dealloc(&dev->sw_dev);
}

#endif

int erdma_create_ah(struct ib_ah *ibah,
#ifdef HAVE_CREATE_AH_RDMA_INIT_ATTR
		    struct rdma_ah_init_attr *init_attr,
#else
		    struct rdma_ah_attr *ah_attr, u32 flags,
#endif
		    struct ib_udata *udata)
{
#ifdef HAVE_ERDMA_MAD
	return sw_create_ah(ibah, init_attr->ah_attr, udata);
#else
	return -EOPNOTSUPP;
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
	return ERR_PTR(-EOPNOTSUPP);
}
#endif

#ifdef HAVE_AH_CORE_ALLOCATION_DESTROY_RC
int erdma_destroy_ah(struct ib_ah *ibah, u32 flags)
#elif defined(HAVE_AH_CORE_ALLOCATION) && defined (HAVE_DESTROY_AH_VOID)
void erdma_destroy_ah(struct ib_ah *ibah, u32 flags)
#elif defined(HAVE_DESTROY_AH_FLAGS)
int erdma_destroy_ah(struct ib_ah *ibah, u32 flags)
#else
int erdma_destroy_ah(struct ib_ah *ibah)
#endif
{
#ifdef HAVE_ERDMA_MAD
	struct sw_ah *ah = to_rah(ibah);

	sw_drop_ref(ah);
#endif

#if defined(HAVE_AH_CORE_ALLOCATION) && defined (HAVE_DESTROY_AH_VOID) &&                  \
	!defined(HAVE_AH_CORE_ALLOCATION_DESTROY_RC)
	return;
#else
#ifdef HAVE_ERDMA_MAD
	return 0;
#else
	return -EOPNOTSUPP;
#endif
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

	lqpn &= 0xFFFFF;
	rqpn &= 0xFFFFF;

	if (dip < sip || (dip == sip && lqpn < rqpn))
		select_type = 0;

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
	enum rdma_network_type ntype;
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
	err = ib_get_cached_gid(&qp->dev->ibdev, rdma_ah_get_port_num(ah_attr),
				rdma_ah_read_grh(ah_attr)->sgid_index, &sgid,
				&sgid_attr);
	if (err)
		return err;

	ntype = ib_gid_to_network_type(sgid_attr.gid_type, &sgid);

	if (sgid_attr.ndev)
		dev_put(sgid_attr.ndev);
#endif

	ibdev_dbg(&qp->dev->ibdev, "gid type:%u, sgid: %pI6\n", ntype,
		  sgid.raw);

	rdma_gid2ip((struct sockaddr *)&qp->attrs.laddr, &sgid);
	rdma_gid2ip((struct sockaddr *)&qp->attrs.raddr,
		    &rdma_ah_read_grh(ah_attr)->dgid);

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
	ibdev_dbg(&qp->dev->ibdev, "attr mask: %x, av: %d, state:%d\n",
		  attr_mask, attr_mask & IB_QP_AV, attr_mask & IB_QP_STATE);

	if (attr_mask & IB_QP_AV)
		erdma_av_from_attr(qp, attr);

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
		ret = __sock_create(net, AF_INET,
				    SOCK_STREAM, IPPROTO_TCP, &rsvd_sock[i], 1);
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
	return erdma_port_init(net, node->rsvd_sock);
}

static void __net_exit erdma_exit_batch_net(struct list_head *net_list)
{
	struct net *net;
	LIST_HEAD(list);

	rtnl_lock();
	list_for_each_entry(net, net_list, exit_list) {
		struct erdma_net *node = net_generic(net, erdma_net_id);
		erdma_port_release(node->rsvd_sock);
	}
	rtnl_unlock();
}

static struct pernet_operations erdma_net_ops = {
	.init = erdma_init_net,
	.exit_batch = erdma_exit_batch_net,
	.id   = &erdma_net_id,
	.size = sizeof(struct erdma_net),
};

int erdma_compat_init(void)
{
	int ret;

	if (!compat_mode)
		return 0;

#ifdef HAVE_ERDMA_MAD
	ret = sw_net_init();
	if (ret)
		return ret;
#endif

	ret = register_pernet_subsys(&erdma_net_ops);
#ifdef HAVE_ERDMA_MAD
	if (ret)
		sw_net_exit();
#endif

	return ret;
}

void erdma_compat_exit(void)
{
	if (!compat_mode)
		return;

	unregister_pernet_subsys(&erdma_net_ops);

#ifdef HAVE_ERDMA_MAD
	sw_net_exit();
#endif
}
