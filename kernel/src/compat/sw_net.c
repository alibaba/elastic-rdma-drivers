// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
 * Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.
 */

#include <linux/skbuff.h>
#include <linux/if_arp.h>
#include <linux/netdevice.h>
#include <linux/if.h>
#include <linux/if_vlan.h>
#include <net/udp_tunnel.h>
#include <net/sch_generic.h>
#include <linux/netfilter.h>
#include <rdma/ib_addr.h>

#include "sw.h"
#include "sw_net.h"
#include "sw_loc.h"
#include "../erdma_verbs.h"

static struct sw_recv_sockets recv_sockets;

int sw_mcast_add(struct sw_dev *sw, union ib_gid *mgid)
{
	int err;
	unsigned char ll_addr[ETH_ALEN];

	ipv6_eth_mc_map((struct in6_addr *)mgid->raw, ll_addr);
	err = dev_mc_add(sw->ndev, ll_addr);

	return err;
}

int sw_mcast_delete(struct sw_dev *sw, union ib_gid *mgid)
{
	int err;
	unsigned char ll_addr[ETH_ALEN];

	ipv6_eth_mc_map((struct in6_addr *)mgid->raw, ll_addr);
	err = dev_mc_del(sw->ndev, ll_addr);

	return err;
}

static struct dst_entry *sw_find_route4(struct net_device *ndev,
				  struct in_addr *saddr,
				  struct in_addr *daddr)
{
	struct rtable *rt;
	struct flowi4 fl = { { 0 } };

	memset(&fl, 0, sizeof(fl));
	fl.flowi4_oif = ndev->ifindex;
	memcpy(&fl.saddr, saddr, sizeof(*saddr));
	memcpy(&fl.daddr, daddr, sizeof(*daddr));
	fl.flowi4_proto = IPPROTO_UDP;

	rt = ip_route_output_key(&init_net, &fl);
	if (IS_ERR(rt)) {
		pr_err_ratelimited("no route to %pI4\n", &daddr->s_addr);
		return NULL;
	}

	return &rt->dst;
}

static struct dst_entry *sw_find_route6(struct net_device *ndev,
					 struct in6_addr *saddr,
					 struct in6_addr *daddr)
{
	return NULL;
}

static struct dst_entry *sw_find_route(struct net_device *ndev,
					struct sw_qp *qp,
					struct sw_av *av)
{
	struct dst_entry *dst = NULL;

	if (qp_type(qp) == IB_QPT_RC)
		dst = sk_dst_get(qp->sk->sk);

	if (!dst || !dst_check(dst, qp->dst_cookie)) {
		if (dst)
			dst_release(dst);

		if (av->network_type == SW_NETWORK_TYPE_IPV4) {
			struct in_addr *saddr;
			struct in_addr *daddr;

			saddr = &av->sgid_addr._sockaddr_in.sin_addr;
			daddr = &av->dgid_addr._sockaddr_in.sin_addr;
			dst = sw_find_route4(ndev, saddr, daddr);
		} else if (av->network_type == SW_NETWORK_TYPE_IPV6) {
			struct in6_addr *saddr6;
			struct in6_addr *daddr6;

			saddr6 = &av->sgid_addr._sockaddr_in6.sin6_addr;
			daddr6 = &av->dgid_addr._sockaddr_in6.sin6_addr;
			dst = sw_find_route6(ndev, saddr6, daddr6);
#if IS_ENABLED(CONFIG_IPV6)
			if (dst)
				qp->dst_cookie =
					rt6_get_cookie((struct rt6_info *)dst);
#endif
		}

		if (dst && (qp_type(qp) == IB_QPT_RC)) {
			dst_hold(dst);
			sk_dst_set(qp->sk->sk, dst);
		}
	}
	return dst;
}

static int sw_udp_encap_recv(struct sock *sk, struct sk_buff *skb)
{
	struct udphdr *udph;
	struct net_device *ndev = skb->dev;
	struct net_device *rdev = ndev;
	struct sw_dev *sw = sw_get_dev_from_net(ndev);
	struct sw_pkt_info *pkt = SKB_TO_PKT(skb);

	if (!sw && is_vlan_dev(rdev)) {
		rdev = vlan_dev_real_dev(ndev);
		sw = sw_get_dev_from_net(rdev);
	}
	if (!sw)
		goto drop;

	if (skb_linearize(skb)) {
		pr_err("skb_linearize failed\n");
		ib_device_put(&sw->master->ibdev);
		goto drop;
	}

	udph = udp_hdr(skb);
	pkt->sw = sw;
	pkt->port_num = 1;
	pkt->hdr = (u8 *)(udph + 1);
	pkt->mask = SW_GRH_MASK;
	pkt->paylen = be16_to_cpu(udph->len) - sizeof(*udph);

	sw_rcv(skb);

	/*
	 * FIXME: this is in the wrong place, it needs to be done when pkt is
	 * destroyed
	 */
	ib_device_put(&sw->master->ibdev);

	return 0;
drop:
	kfree_skb(skb);

	return 0;
}

struct socket *sw_setup_udp_tunnel(struct net *net, __be16 port,
					   bool ipv6)
{
	int err;
	struct socket *sock;
	struct udp_port_cfg udp_cfg = { };
	struct udp_tunnel_sock_cfg tnl_cfg = { };

	if (ipv6) {
		udp_cfg.family = AF_INET6;
		udp_cfg.ipv6_v6only = 1;
	} else {
		udp_cfg.family = AF_INET;
	}

	udp_cfg.local_udp_port = port;

	/* Create UDP socket */
	err = udp_sock_create(net, &udp_cfg, &sock);
	if (err < 0)
		return ERR_PTR(err);

	tnl_cfg.encap_type = 1;
	tnl_cfg.encap_rcv = sw_udp_encap_recv;

	/* Setup UDP tunnel */
	setup_udp_tunnel_sock(net, sock, &tnl_cfg);

	return sock;
}

static void sw_release_udp_tunnel(struct socket *sk)
{
	if (sk)
		udp_tunnel_sock_release(sk);
}

static void prepare_udp_hdr(struct sk_buff *skb, __be16 src_port,
			    __be16 dst_port)
{
	struct udphdr *udph;

	__skb_push(skb, sizeof(*udph));
	skb_reset_transport_header(skb);
	udph = udp_hdr(skb);

	udph->dest = dst_port;
	udph->source = src_port;
	udph->len = htons(skb->len);
	udph->check = 0;
}

static void prepare_ipv4_hdr(struct dst_entry *dst, struct sk_buff *skb,
			     __be32 saddr, __be32 daddr, __u8 proto,
			     __u8 tos, __u8 ttl, __be16 df, bool xnet)
{
	struct iphdr *iph;

	skb_scrub_packet(skb, xnet);

	skb_clear_hash(skb);
	skb_dst_set(skb, dst_clone(dst));
	memset(IPCB(skb), 0, sizeof(*IPCB(skb)));

	skb_push(skb, sizeof(struct iphdr));
	skb_reset_network_header(skb);

	iph = ip_hdr(skb);

	iph->version	=	IPVERSION;
	iph->ihl	=	sizeof(struct iphdr) >> 2;
	iph->frag_off	=	df;
	iph->protocol	=	proto;
	iph->tos	=	tos;
	iph->daddr	=	daddr;
	iph->saddr	=	saddr;
	iph->ttl	=	ttl;
	__ip_select_ident(dev_net(dst->dev), iph,
			  skb_shinfo(skb)->gso_segs ?: 1);
	iph->tot_len = htons(skb->len);
	ip_send_check(iph);
}

static void prepare_ipv6_hdr(struct dst_entry *dst, struct sk_buff *skb,
			     struct in6_addr *saddr, struct in6_addr *daddr,
			     __u8 proto, __u8 prio, __u8 ttl)
{
	struct ipv6hdr *ip6h;

	memset(&(IPCB(skb)->opt), 0, sizeof(IPCB(skb)->opt));
	IPCB(skb)->flags &= ~(IPSKB_XFRM_TUNNEL_SIZE | IPSKB_XFRM_TRANSFORMED
			    | IPSKB_REROUTED);
	skb_dst_set(skb, dst_clone(dst));

	__skb_push(skb, sizeof(*ip6h));
	skb_reset_network_header(skb);
	ip6h		  = ipv6_hdr(skb);
	ip6_flow_hdr(ip6h, prio, htonl(0));
	ip6h->payload_len = htons(skb->len);
	ip6h->nexthdr     = proto;
	ip6h->hop_limit   = ttl;
	ip6h->daddr	  = *daddr;
	ip6h->saddr	  = *saddr;
	ip6h->payload_len = htons(skb->len - sizeof(*ip6h));
}

static int prepare4(struct sw_pkt_info *pkt, struct sk_buff *skb)
{
	struct sw_qp *qp = pkt->qp;
	struct dst_entry *dst;
	bool xnet = false;
	__be16 df = htons(IP_DF);
	struct sw_av *av = sw_get_av(pkt);
	struct in_addr *saddr = &av->sgid_addr._sockaddr_in.sin_addr;
	struct in_addr *daddr = &av->dgid_addr._sockaddr_in.sin_addr;

	dst = sw_find_route(skb->dev, qp, av);
	if (!dst) {
		pr_err("Host not reachable\n");
		return -EHOSTUNREACH;
	}

	prepare_udp_hdr(skb, cpu_to_be16(qp->src_port),
			cpu_to_be16(ROCE_V2_UDP_DPORT));

	prepare_ipv4_hdr(dst, skb, saddr->s_addr, daddr->s_addr, IPPROTO_UDP,
			 av->grh.traffic_class, av->grh.hop_limit, df, xnet);

	dst_release(dst);
	return 0;
}

static int prepare6(struct sw_pkt_info *pkt, struct sk_buff *skb)
{
	struct sw_qp *qp = pkt->qp;
	struct dst_entry *dst;
	struct sw_av *av = sw_get_av(pkt);
	struct in6_addr *saddr = &av->sgid_addr._sockaddr_in6.sin6_addr;
	struct in6_addr *daddr = &av->dgid_addr._sockaddr_in6.sin6_addr;

	dst = sw_find_route(skb->dev, qp, av);
	if (!dst) {
		pr_err("Host not reachable\n");
		return -EHOSTUNREACH;
	}

	prepare_udp_hdr(skb, cpu_to_be16(qp->src_port),
			cpu_to_be16(ROCE_V2_UDP_DPORT));

	prepare_ipv6_hdr(dst, skb, saddr, daddr, IPPROTO_UDP,
			 av->grh.traffic_class,
			 av->grh.hop_limit);

	dst_release(dst);
	return 0;
}

int sw_prepare(struct sw_pkt_info *pkt, struct sk_buff *skb, u32 *crc)
{
	int err = 0;

	if (skb->protocol == htons(ETH_P_IP))
		err = prepare4(pkt, skb);
	else if (skb->protocol == htons(ETH_P_IPV6))
		err = prepare6(pkt, skb);

	*crc = sw_icrc_hdr(pkt, skb);

	if (ether_addr_equal(skb->dev->dev_addr, sw_get_av(pkt)->dmac))
		pkt->mask |= SW_LOOPBACK_MASK;

	return err;
}

static void sw_skb_tx_dtor(struct sk_buff *skb)
{
	struct sock *sk = skb->sk;
	struct sw_qp *qp = sk->sk_user_data;
	int skb_out = atomic_dec_return(&qp->skb_out);

	if (unlikely(qp->need_req_skb &&
		     skb_out < SW_INFLIGHT_SKBS_PER_QP_LOW))
		sw_run_task(&qp->req.task, 1);

	sw_drop_ref(qp);
}

int sw_send(struct sw_pkt_info *pkt, struct sk_buff *skb)
{
	int err;

	skb->destructor = sw_skb_tx_dtor;
	skb->sk = pkt->qp->sk->sk;

	sw_add_ref(pkt->qp);
	atomic_inc(&pkt->qp->skb_out);

	if (skb->protocol == htons(ETH_P_IP)) {
#ifndef HAVE_IP_LOCAL_OUT_SKB
		err = ip_local_out(dev_net(skb_dst(skb)->dev), skb->sk, skb);
#else
		err = ip_local_out(skb);
#endif
	} else {
		pr_err("Unknown layer 3 protocol: %d\n", skb->protocol);
		atomic_dec(&pkt->qp->skb_out);
		sw_drop_ref(pkt->qp);
		kfree_skb(skb);
		return -EINVAL;
	}

	if (unlikely(net_xmit_eval(err))) {
		pr_debug("error sending packet: %d\n", err);
		return -EAGAIN;
	}

	return 0;
}

void sw_loopback(struct sk_buff *skb)
{
	if (skb->protocol == htons(ETH_P_IP))
		skb_pull(skb, sizeof(struct iphdr));
	else
		skb_pull(skb, sizeof(struct ipv6hdr));

	sw_rcv(skb);
}

struct sk_buff *sw_init_packet(struct sw_dev *sw, struct sw_av *av,
				int paylen, struct sw_pkt_info *pkt)
{
	unsigned int hdr_len;
	struct sk_buff *skb = NULL;
	struct net_device *ndev;
	const struct ib_gid_attr *attr;
	const int port_num = 1;

#ifdef HAVE_RDMA_GID_API
	attr = rdma_get_gid_attr(&sw->master->ibdev, port_num, av->grh.sgid_index);
	if (IS_ERR(attr))
		return NULL;
#else
	pr_err_once("Unexcepted branch, does not support this OS.\n");
	return NULL;
#endif

	if (av->network_type == SW_NETWORK_TYPE_IPV4)
		hdr_len = ETH_HLEN + sizeof(struct udphdr) +
			sizeof(struct iphdr);
	else
		hdr_len = ETH_HLEN + sizeof(struct udphdr) +
			sizeof(struct ipv6hdr);

	rcu_read_lock();
#ifdef HAVE_RDMA_READ_GID_ATTR_NDEV_RCU
	ndev = rdma_read_gid_attr_ndev_rcu(attr);
#else
	ndev = attr->ndev;
#endif
	if (IS_ERR(ndev)) {
		rcu_read_unlock();
		goto out;
	}
	skb = alloc_skb(paylen + hdr_len + LL_RESERVED_SPACE(ndev),
			GFP_ATOMIC);

	if (unlikely(!skb)) {
		rcu_read_unlock();
		goto out;
	}

	skb_reserve(skb, hdr_len + LL_RESERVED_SPACE(ndev));

	/* FIXME: hold reference to this netdev until life of this skb. */
	skb->dev	= ndev;
	rcu_read_unlock();

	if (av->network_type == SW_NETWORK_TYPE_IPV4)
		skb->protocol = htons(ETH_P_IP);
	else
		skb->protocol = htons(ETH_P_IPV6);

	pkt->sw	= sw;
	pkt->port_num	= port_num;
	pkt->hdr	= skb_put_zero(skb, paylen);
	pkt->mask	|= SW_GRH_MASK;

out:
#ifdef HAVE_RDMA_GID_API
	rdma_put_gid_attr(attr);
#endif
	return skb;
}

/*
 * this is required by sw_cfg to match sw devices in
 * /sys/class/infiniband up with their underlying ethernet devices
 */
const char *sw_parent_name(struct sw_dev *sw, unsigned int port_num)
{
	return sw->ndev->name;
}

static void sw_port_event(struct sw_dev *sw,
			   enum ib_event_type event)
{
	struct ib_event ev;

	ev.device = &sw->ib_dev;
	ev.element.port_num = 1;
	ev.event = event;

	ib_dispatch_event(&ev);
}

/* Caller must hold net_info_lock */
void sw_port_up(struct sw_dev *sw)
{
	struct sw_port *port;

	port = &sw->port;
	port->attr.state = IB_PORT_ACTIVE;

	sw_port_event(sw, IB_EVENT_PORT_ACTIVE);
	dev_info(&sw->ib_dev.dev, "set active\n");
}

/* Caller must hold net_info_lock */
void sw_port_down(struct sw_dev *sw)
{
	struct sw_port *port;

	port = &sw->port;
	port->attr.state = IB_PORT_DOWN;

	sw_port_event(sw, IB_EVENT_PORT_ERR);
	sw_counter_inc(sw, SW_CNT_LINK_DOWNED);
	dev_info(&sw->ib_dev.dev, "set down\n");
}

void sw_set_port_state(struct sw_dev *sw)
{
	if (netif_running(sw->ndev) && netif_carrier_ok(sw->ndev))
		sw_port_up(sw);
	else
		sw_port_down(sw);
}

static int sw_net_ipv4_init(void)
{
	recv_sockets.sk4 = sw_setup_udp_tunnel(&init_net,
				htons(ROCE_V2_UDP_DPORT), false);
	if (IS_ERR(recv_sockets.sk4)) {
		recv_sockets.sk4 = NULL;
		pr_err("Failed to create IPv4 UDP tunnel\n");
		return -1;
	}

	return 0;
}

void sw_net_exit(void)
{
	sw_release_udp_tunnel(recv_sockets.sk6);
	sw_release_udp_tunnel(recv_sockets.sk4);
}

int sw_net_init(void)
{
	recv_sockets.sk6 = NULL;

	return sw_net_ipv4_init();
}
