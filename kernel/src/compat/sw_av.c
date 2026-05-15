// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
 * Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.
 */

#include "sw.h"
#include "sw_loc.h"

void sw_init_av(struct ib_device *ibdev, struct rdma_ah_attr *attr, struct sw_av *av)
{
	sw_av_from_attr(rdma_ah_get_port_num(attr), av, attr);
	sw_av_fill_ip_info(ibdev, av, attr);
	memcpy(av->dmac, attr->roce.dmac, ETH_ALEN);
}

int sw_av_chk_attr(struct sw_dev *sw, struct rdma_ah_attr *attr)
{
	const struct ib_global_route *grh = rdma_ah_read_grh(attr);
#ifndef HAVE_IB_GLOBAL_ROUTE_WITH_SGID_ATTR
	struct ib_gid_attr sgid_attr;
	union ib_gid sgid;
	int err;
#endif
	struct sw_port *port;
	int type;

	port = &sw->port;

	if (rdma_ah_get_ah_flags(attr) & IB_AH_GRH) {
		if (grh->sgid_index > port->attr.gid_tbl_len) {
			pr_warn("invalid sgid index = %d\n",
					grh->sgid_index);
			return -EINVAL;
		}

#ifdef HAVE_IB_GLOBAL_ROUTE_WITH_SGID_ATTR
		type = rdma_gid_attr_network_type(grh->sgid_attr);
#else
		err = ib_get_sgid_attr(&sw->master->ibdev, attr, &sgid,
				       &sgid_attr, &type);
		if (err)
			return err;
#endif

		if (type < RDMA_NETWORK_IPV4 ||
		    type > RDMA_NETWORK_IPV6) {
			pr_warn("invalid network type for rdma_sw = %d\n",
					type);
			return -EINVAL;
		}
	}

	return 0;
}

void sw_av_from_attr(u8 port_num, struct sw_av *av,
		     struct rdma_ah_attr *attr)
{
	const struct ib_global_route *grh = rdma_ah_read_grh(attr);

	memset(av, 0, sizeof(*av));
	memcpy(av->grh.dgid.raw, grh->dgid.raw, sizeof(grh->dgid.raw));
	av->grh.flow_label = grh->flow_label;
	av->grh.sgid_index = grh->sgid_index;
	av->grh.hop_limit = grh->hop_limit;
	av->grh.traffic_class = grh->traffic_class;
	av->port_num = port_num;
}

void sw_av_to_attr(struct sw_av *av, struct rdma_ah_attr *attr)
{
	struct ib_global_route *grh = rdma_ah_retrieve_grh(attr);

	attr->type = RDMA_AH_ATTR_TYPE_ROCE;

	memcpy(grh->dgid.raw, av->grh.dgid.raw, sizeof(av->grh.dgid.raw));
	grh->flow_label = av->grh.flow_label;
	grh->sgid_index = av->grh.sgid_index;
	grh->hop_limit = av->grh.hop_limit;
	grh->traffic_class = av->grh.traffic_class;

	rdma_ah_set_ah_flags(attr, IB_AH_GRH);
	rdma_ah_set_port_num(attr, av->port_num);
}

void sw_av_fill_ip_info(struct ib_device *ibdev, struct sw_av *av, struct rdma_ah_attr *attr)
{
#ifdef HAVE_IB_GLOBAL_ROUTE_WITH_SGID_ATTR
	const struct ib_gid_attr *sgid_attr = attr->grh.sgid_attr;
#else
	struct ib_gid_attr sgid_attr;
	union ib_gid sgid;
	int err;
#endif
	int ibtype;
	int type;

#ifdef HAVE_IB_GLOBAL_ROUTE_WITH_SGID_ATTR
	ibtype = rdma_gid_attr_network_type(sgid_attr);
	rdma_gid2ip((struct sockaddr *)&av->sgid_addr, &sgid_attr->gid);
#else
	err = ib_get_sgid_attr(ibdev, attr, &sgid, &sgid_attr, &ibtype);
	if (err)
		return;
	rdma_gid2ip((struct sockaddr *)&av->sgid_addr, &sgid);
#endif
	rdma_gid2ip((struct sockaddr *)&av->dgid_addr,
		    &rdma_ah_read_grh(attr)->dgid);

	switch (ibtype) {
	case RDMA_NETWORK_IPV4:
		type = SW_NETWORK_TYPE_IPV4;
		break;
	case RDMA_NETWORK_IPV6:
		type = SW_NETWORK_TYPE_IPV6;
		break;
	default:
		/* not reached - checked in sw_av_chk_attr */
		type = 0;
		break;
	}

	av->network_type = type;
}

struct sw_av *sw_get_av(struct sw_pkt_info *pkt)
{
	if (!pkt || !pkt->qp)
		return NULL;

	if (qp_type(pkt->qp) == IB_QPT_RC || qp_type(pkt->qp) == IB_QPT_UC)
		return &pkt->qp->pri_av;

	return (pkt->wqe) ? &pkt->wqe->av : NULL;
}
