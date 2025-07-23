// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
 * Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.
 */

#include <linux/skbuff.h>

#include "sw.h"
#include "sw_loc.h"
#include "../erdma_verbs.h"

/* check that QP matches packet opcode type and is in a valid state */
static int check_type_state(struct sw_dev *sw, struct sw_pkt_info *pkt,
			    struct sw_qp *qp)
{
	unsigned int pkt_type;

	if (unlikely(!qp->valid))
		goto err1;

	pkt_type = pkt->opcode & 0xe0;

	switch (qp_type(qp)) {
	case IB_QPT_RC:
		if (unlikely(pkt_type != IB_OPCODE_RC)) {
			pr_warn_ratelimited("bad qp type\n");
			goto err1;
		}
		break;
	case IB_QPT_UC:
		if (unlikely(pkt_type != IB_OPCODE_UC)) {
			pr_warn_ratelimited("bad qp type\n");
			goto err1;
		}
		break;
	case IB_QPT_UD:
	case IB_QPT_SMI:
	case IB_QPT_GSI:
		if (unlikely(pkt_type != IB_OPCODE_UD)) {
			pr_warn_ratelimited("bad qp type\n");
			goto err1;
		}
		break;
	default:
		pr_warn_ratelimited("unsupported qp type\n");
		goto err1;
	}

	if (pkt->mask & SW_REQ_MASK) {
		if (unlikely(qp->resp.state != QP_STATE_READY))
			goto err1;
	} else if (unlikely(qp->req.state < QP_STATE_READY ||
				qp->req.state > QP_STATE_DRAINED)) {
		goto err1;
	}

	return 0;

err1:
	return -EINVAL;
}

static void set_bad_pkey_cntr(struct sw_port *port)
{
	spin_lock_bh(&port->port_lock);
	port->attr.bad_pkey_cntr = min((u32)0xffff,
				       port->attr.bad_pkey_cntr + 1);
	spin_unlock_bh(&port->port_lock);
}

static void set_qkey_viol_cntr(struct sw_port *port)
{
	spin_lock_bh(&port->port_lock);
	port->attr.qkey_viol_cntr = min((u32)0xffff,
					port->attr.qkey_viol_cntr + 1);
	spin_unlock_bh(&port->port_lock);
}

static int check_keys(struct sw_dev *sw, struct sw_pkt_info *pkt,
		      u32 qpn, struct sw_qp *qp)
{
	struct sw_port *port = &sw->port;
	u16 pkey = bth_pkey(pkt);

	pkt->pkey_index = 0;

	if (!pkey_match(pkey, IB_DEFAULT_PKEY_FULL)) {
		pr_warn_ratelimited("bad pkey = 0x%x\n", pkey);
		set_bad_pkey_cntr(port);
		goto err1;
	}

	if ((qp_type(qp) == IB_QPT_UD || qp_type(qp) == IB_QPT_GSI) &&
	    pkt->mask) {
		u32 qkey = (qpn == 1) ? GSI_QKEY : qp->attr.qkey;

		if (unlikely(deth_qkey(pkt) != qkey)) {
			pr_warn_ratelimited("bad qkey, got 0x%x expected 0x%x for qpn 0x%x\n",
					    deth_qkey(pkt), qkey, qpn);
			set_qkey_viol_cntr(port);
			goto err1;
		}
	}

	return 0;

err1:
	return -EINVAL;
}

static int check_addr(struct sw_dev *sw, struct sw_pkt_info *pkt,
		      struct sw_qp *qp)
{
	struct sk_buff *skb = PKT_TO_SKB(pkt);

	if (qp_type(qp) != IB_QPT_RC && qp_type(qp) != IB_QPT_UC)
		goto done;

	if (unlikely(pkt->port_num != qp->attr.port_num)) {
		pr_warn_ratelimited("port %d != qp port %d\n",
				    pkt->port_num, qp->attr.port_num);
		goto err1;
	}

	if (skb->protocol == htons(ETH_P_IP)) {
		struct in_addr *saddr =
			&qp->pri_av.sgid_addr._sockaddr_in.sin_addr;
		struct in_addr *daddr =
			&qp->pri_av.dgid_addr._sockaddr_in.sin_addr;

		if (ip_hdr(skb)->daddr != saddr->s_addr) {
			pr_warn_ratelimited("dst addr %pI4 != qp source addr %pI4\n",
					    &ip_hdr(skb)->daddr,
					    &saddr->s_addr);
			goto err1;
		}

		if (ip_hdr(skb)->saddr != daddr->s_addr) {
			pr_warn_ratelimited("source addr %pI4 != qp dst addr %pI4\n",
					    &ip_hdr(skb)->saddr,
					    &daddr->s_addr);
			goto err1;
		}

	} else if (skb->protocol == htons(ETH_P_IPV6)) {
		struct in6_addr *saddr =
			&qp->pri_av.sgid_addr._sockaddr_in6.sin6_addr;
		struct in6_addr *daddr =
			&qp->pri_av.dgid_addr._sockaddr_in6.sin6_addr;

		if (memcmp(&ipv6_hdr(skb)->daddr, saddr, sizeof(*saddr))) {
			pr_warn_ratelimited("dst addr %pI6 != qp source addr %pI6\n",
					    &ipv6_hdr(skb)->daddr, saddr);
			goto err1;
		}

		if (memcmp(&ipv6_hdr(skb)->saddr, daddr, sizeof(*daddr))) {
			pr_warn_ratelimited("source addr %pI6 != qp dst addr %pI6\n",
					    &ipv6_hdr(skb)->saddr, daddr);
			goto err1;
		}
	}

done:
	return 0;

err1:
	return -EINVAL;
}

static int hdr_check(struct sw_pkt_info *pkt)
{
	struct sw_dev *sw = pkt->sw;
	struct sw_port *port = &sw->port;
	struct erdma_qp *master_qp;
	struct sw_qp *qp = NULL;
	u32 qpn = bth_qpn(pkt);
	int index;
	int err;

	if (unlikely(bth_tver(pkt) != BTH_TVER)) {
		pr_warn_ratelimited("bad tver\n");
		goto err1;
	}

	if (unlikely(qpn == 0)) {
		pr_warn_once("QP 0 not supported");
		goto err1;
	}

	if (qpn != IB_MULTICAST_QPN) {
		index = (qpn == 1) ? port->qp_gsi_index : qpn;

		master_qp = find_qp_by_qpn(sw->master, qpn);			/* gsi qpn pr_info -----*/
		if (unlikely(!master_qp || master_qp->attrs.flags & ERDMA_QP_IN_DESTROY)) {
			pr_warn_ratelimited("no qp matches qpn 0x%x\n", qpn);
			goto err1;
		}

		//qp = sw_pool_get_index(&sw->qp_pool, index);
		qp = master_qp->sw_qp;
		if (unlikely(!qp)) {
			pr_warn_ratelimited("no qp matches qpn 0x%x\n", qpn);
			goto err1;
		}
		sw_add_ref(qp);

		err = check_type_state(sw, pkt, qp);
		if (unlikely(err))
			goto err2;

		err = check_addr(sw, pkt, qp);
		if (unlikely(err))
			goto err2;

		err = check_keys(sw, pkt, qpn, qp);
		if (unlikely(err))
			goto err2;
	} else {
		if (unlikely((pkt->mask & SW_GRH_MASK) == 0)) {
			pr_warn_ratelimited("no grh for mcast qpn\n");
			goto err1;
		}
	}

	pkt->qp = qp;
	return 0;

err2:
	sw_drop_ref(qp);
err1:
	return -EINVAL;
}

static inline void sw_rcv_pkt(struct sw_pkt_info *pkt, struct sk_buff *skb)
{
	if (pkt->mask & SW_REQ_MASK)
		sw_resp_queue_pkt(pkt->qp, skb);
	else
		sw_comp_queue_pkt(pkt->qp, skb);
}

static void sw_rcv_mcast_pkt(struct sw_dev *sw, struct sk_buff *skb)
{
	struct sw_pkt_info *pkt = SKB_TO_PKT(skb);
	struct sw_mc_grp *mcg;
	struct sw_mc_elem *mce;
	struct sw_qp *qp;
	union ib_gid dgid;
	struct sk_buff *per_qp_skb;
	struct sw_pkt_info *per_qp_pkt;
	int err;

	if (skb->protocol == htons(ETH_P_IP))
		ipv6_addr_set_v4mapped(ip_hdr(skb)->daddr,
				       (struct in6_addr *)&dgid);
	else if (skb->protocol == htons(ETH_P_IPV6))
		memcpy(&dgid, &ipv6_hdr(skb)->daddr, sizeof(dgid));

	/* lookup mcast group corresponding to mgid, takes a ref */
	mcg = sw_pool_get_key(&sw->mc_grp_pool, &dgid);
	if (!mcg)
		goto err1;	/* mcast group not registered */

	spin_lock_bh(&mcg->mcg_lock);

	list_for_each_entry(mce, &mcg->qp_list, qp_list) {
		qp = mce->qp;

		/* validate qp for incoming packet */
		err = check_type_state(sw, pkt, qp);
		if (err)
			continue;

		err = check_keys(sw, pkt, bth_qpn(pkt), qp);
		if (err)
			continue;

		/* for all but the last qp create a new clone of the
		 * skb and pass to the qp. If an error occurs in the
		 * checks for the last qp in the list we need to
		 * free the skb since it hasn't been passed on to
		 * sw_rcv_pkt() which would free it later.
		 */
		if (mce->qp_list.next != &mcg->qp_list) {
			per_qp_skb = skb_clone(skb, GFP_ATOMIC);
		} else {
			per_qp_skb = skb;
			/* show we have consumed the skb */
			skb = NULL;
		}

		if (unlikely(!per_qp_skb))
			continue;

		per_qp_pkt = SKB_TO_PKT(per_qp_skb);
		per_qp_pkt->qp = qp;
		sw_add_ref(qp);
		sw_rcv_pkt(per_qp_pkt, per_qp_skb);
	}

	spin_unlock_bh(&mcg->mcg_lock);

	sw_drop_ref(mcg);	/* drop ref from sw_pool_get_key. */

err1:
	/* free skb if not consumed */
	kfree_skb(skb);
}

/**
 * sw_chk_dgid - validate destination IP address
 * @sw: sw device that received packet
 * @skb: the received packet buffer
 *
 * Accept any loopback packets
 * Extract IP address from packet and
 * Accept if multicast packet
 * Accept if matches an SGID table entry
 */
static int sw_chk_dgid(struct sw_dev *sw, struct sk_buff *skb)
{
	struct sw_pkt_info *pkt = SKB_TO_PKT(skb);
#ifdef HAVE_RDMA_FIND_GID_BY_PORT
	const struct ib_gid_attr *gid_attr;
#endif
	union ib_gid dgid;
	union ib_gid *pdgid;

	if (pkt->mask & SW_LOOPBACK_MASK)
		return 0;

	if (skb->protocol == htons(ETH_P_IP)) {
		ipv6_addr_set_v4mapped(ip_hdr(skb)->daddr,
				       (struct in6_addr *)&dgid);
		pdgid = &dgid;
	} else {
		pdgid = (union ib_gid *)&ipv6_hdr(skb)->daddr;
	}

	if (rdma_is_multicast_addr((struct in6_addr *)pdgid))
		return 0;

#ifdef HAVE_RDMA_FIND_GID_BY_PORT
	gid_attr = rdma_find_gid_by_port(&sw->master->ibdev, pdgid,
					 IB_GID_TYPE_ROCE_UDP_ENCAP,
					 1, skb->dev);
	if (IS_ERR(gid_attr))
		return PTR_ERR(gid_attr);
#else
	/* Stub for old kernel. */
	pr_err_once("Unexcepted branch, does not support this OS.\n");
	return -EINVAL;
#endif

#ifdef HAVE_RDMA_GID_API
	rdma_put_gid_attr(gid_attr);
#endif
	return 0;
}

/* sw_rcv is called from the interface driver */
void sw_rcv(struct sk_buff *skb)
{
	int err;
	struct sw_pkt_info *pkt = SKB_TO_PKT(skb);
	struct sw_dev *sw = pkt->sw;
	__be32 *icrcp;
	u32 calc_icrc, pack_icrc;

	pkt->offset = 0;

	if (unlikely(skb->len < pkt->offset + SW_BTH_BYTES))
		goto drop;

	if (sw_chk_dgid(sw, skb) < 0) {
		pr_warn_ratelimited("failed checking dgid\n");
		goto drop;
	}

	pkt->opcode = bth_opcode(pkt);
	pkt->psn = bth_psn(pkt);
	pkt->qp = NULL;
	pkt->mask |= sw_opcode[pkt->opcode].mask;

	if (unlikely(skb->len < header_size(pkt)))
		goto drop;

	err = hdr_check(pkt);
	if (unlikely(err))
		goto drop;

	/* Verify ICRC */
	icrcp = (__be32 *)(pkt->hdr + pkt->paylen - SW_ICRC_SIZE);
	pack_icrc = be32_to_cpu(*icrcp);

	calc_icrc = sw_icrc_hdr(pkt, skb);
	calc_icrc = sw_crc32(sw, calc_icrc, (u8 *)payload_addr(pkt),
			      payload_size(pkt) + bth_pad(pkt));
	calc_icrc = (__force u32)cpu_to_be32(~calc_icrc);
	if (unlikely(calc_icrc != pack_icrc)) {
		if (skb->protocol == htons(ETH_P_IPV6))
			pr_warn_ratelimited("bad ICRC from %pI6c\n",
					    &ipv6_hdr(skb)->saddr);
		else if (skb->protocol == htons(ETH_P_IP))
			pr_warn_ratelimited("bad ICRC from %pI4\n",
					    &ip_hdr(skb)->saddr);
		else
			pr_warn_ratelimited("bad ICRC from unknown\n");

		goto drop;
	}

	sw_counter_inc(sw, SW_CNT_RCVD_PKTS);

	if (unlikely(bth_qpn(pkt) == IB_MULTICAST_QPN))
		sw_rcv_mcast_pkt(sw, skb);
	else
		sw_rcv_pkt(pkt, skb);

	return;

drop:
	if (pkt->qp)
		sw_drop_ref(pkt->qp);

	kfree_skb(skb);
}
