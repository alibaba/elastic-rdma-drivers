// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
 * Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.
 */

#include <rdma/rdma_netlink.h>
#include <net/addrconf.h>
#include "sw.h"
#include "sw_loc.h"

MODULE_AUTHOR("Bob Pearson, Frank Zago, John Groves, Kamal Heib");
MODULE_DESCRIPTION("Soft RDMA transport");
MODULE_LICENSE("Dual BSD/GPL");

bool sw_initialized;

/* free resources for a sw device all objects created for this device must
 * have been destroyed
 */
void sw_dealloc(struct sw_dev *sw)
{
	sw_pool_cleanup(&sw->uc_pool);
	sw_pool_cleanup(&sw->pd_pool);
	sw_pool_cleanup(&sw->ah_pool);
	sw_pool_cleanup(&sw->srq_pool);
	sw_pool_cleanup(&sw->qp_pool);
	sw_pool_cleanup(&sw->cq_pool);
	sw_pool_cleanup(&sw->mr_pool);
	sw_pool_cleanup(&sw->mw_pool);
	sw_pool_cleanup(&sw->mc_grp_pool);
	sw_pool_cleanup(&sw->mc_elem_pool);

	if (sw->tfm)
		crypto_free_shash(sw->tfm);
}

/* initialize sw device parameters */
static void sw_init_device_param(struct sw_dev *sw)
{
	sw->max_inline_data			= SW_MAX_INLINE_DATA;

	sw->attr.vendor_id			= SW_VENDOR_ID;
	sw->attr.max_mr_size			= SW_MAX_MR_SIZE;
	sw->attr.page_size_cap			= SW_PAGE_SIZE_CAP;
	sw->attr.max_qp			= SW_MAX_QP;
	sw->attr.max_qp_wr			= SW_MAX_QP_WR;
	sw->attr.device_cap_flags		= SW_DEVICE_CAP_FLAGS;
#ifdef HAVE_MAX_SEND_RCV_SGE
	sw->attr.max_send_sge			= SW_MAX_SGE;
	sw->attr.max_recv_sge			= SW_MAX_SGE;
#else
	sw->attr.max_sge			= SW_MAX_SGE;
#endif

	sw->attr.max_sge_rd			= SW_MAX_SGE_RD;
	sw->attr.max_cq			= SW_MAX_CQ;
	sw->attr.max_cqe			= (1 << SW_MAX_LOG_CQE) - 1;
	sw->attr.max_mr			= SW_MAX_MR;
	sw->attr.max_pd			= SW_MAX_PD;
	sw->attr.max_qp_rd_atom		= SW_MAX_QP_RD_ATOM;
	sw->attr.max_res_rd_atom		= SW_MAX_RES_RD_ATOM;
	sw->attr.max_qp_init_rd_atom		= SW_MAX_QP_INIT_RD_ATOM;
	sw->attr.atomic_cap			= IB_ATOMIC_HCA;
	sw->attr.max_mcast_grp			= SW_MAX_MCAST_GRP;
	sw->attr.max_mcast_qp_attach		= SW_MAX_MCAST_QP_ATTACH;
	sw->attr.max_total_mcast_qp_attach	= SW_MAX_TOT_MCAST_QP_ATTACH;
	sw->attr.max_ah			= SW_MAX_AH;
	sw->attr.max_srq			= SW_MAX_SRQ;
	sw->attr.max_srq_wr			= SW_MAX_SRQ_WR;
	sw->attr.max_srq_sge			= SW_MAX_SRQ_SGE;
	sw->attr.max_fast_reg_page_list_len	= SW_MAX_FMR_PAGE_LIST_LEN;
	sw->attr.max_pkeys			= SW_MAX_PKEYS;
	sw->attr.local_ca_ack_delay		= SW_LOCAL_CA_ACK_DELAY;
	addrconf_addr_eui48((unsigned char *)&sw->attr.sys_image_guid,
			sw->ndev->dev_addr);

	sw->max_ucontext			= SW_MAX_UCONTEXT;
}

/* initialize port attributes */
static void sw_init_port_param(struct sw_port *port)
{
	port->attr.state		= IB_PORT_DOWN;
	port->attr.max_mtu		= IB_MTU_4096;
	port->attr.active_mtu		= IB_MTU_256;
	port->attr.gid_tbl_len		= SW_PORT_GID_TBL_LEN;
	port->attr.port_cap_flags	= SW_PORT_PORT_CAP_FLAGS;
	port->attr.max_msg_sz		= SW_PORT_MAX_MSG_SZ;
	port->attr.bad_pkey_cntr	= SW_PORT_BAD_PKEY_CNTR;
	port->attr.qkey_viol_cntr	= SW_PORT_QKEY_VIOL_CNTR;
	port->attr.pkey_tbl_len		= SW_PORT_PKEY_TBL_LEN;
	port->attr.lid			= SW_PORT_LID;
	port->attr.sm_lid		= SW_PORT_SM_LID;
	port->attr.lmc			= SW_PORT_LMC;
	port->attr.max_vl_num		= SW_PORT_MAX_VL_NUM;
	port->attr.sm_sl		= SW_PORT_SM_SL;
	port->attr.subnet_timeout	= SW_PORT_SUBNET_TIMEOUT;
	port->attr.init_type_reply	= SW_PORT_INIT_TYPE_REPLY;
	port->attr.active_width		= SW_PORT_ACTIVE_WIDTH;
	port->attr.active_speed		= SW_PORT_ACTIVE_SPEED;
	port->mtu_cap			= ib_mtu_enum_to_int(IB_MTU_256);
	port->subnet_prefix		= cpu_to_be64(SW_PORT_SUBNET_PREFIX);
}

/* initialize port state, note IB convention that HCA ports are always
 * numbered from 1
 */
void sw_init_ports(struct sw_dev *sw)
{
	struct sw_port *port = &sw->port;

	sw_init_port_param(port);
	addrconf_addr_eui48((unsigned char *)&port->port_guid,
			    sw->ndev->dev_addr);
	spin_lock_init(&port->port_lock);
}

/* init pools of managed objects */
static int sw_init_pools(struct sw_dev *sw)
{
	int err;

	err = sw_pool_init(sw, &sw->uc_pool, SW_TYPE_UC,
			    sw->max_ucontext);
	if (err)
		goto err1;

	err = sw_pool_init(sw, &sw->pd_pool, SW_TYPE_PD,
			    sw->attr.max_pd);
	if (err)
		goto err2;

	err = sw_pool_init(sw, &sw->ah_pool, SW_TYPE_AH,
			    sw->attr.max_ah);
	if (err)
		goto err3;

	err = sw_pool_init(sw, &sw->srq_pool, SW_TYPE_SRQ,
			    sw->attr.max_srq);
	if (err)
		goto err4;

	err = sw_pool_init(sw, &sw->qp_pool, SW_TYPE_QP,
			    sw->attr.max_qp);
	if (err)
		goto err5;

	err = sw_pool_init(sw, &sw->cq_pool, SW_TYPE_CQ,
			    sw->attr.max_cq);
	if (err)
		goto err6;

	err = sw_pool_init(sw, &sw->mr_pool, SW_TYPE_MR,
			    sw->attr.max_mr);
	if (err)
		goto err7;

	err = sw_pool_init(sw, &sw->mw_pool, SW_TYPE_MW,
			    sw->attr.max_mw);
	if (err)
		goto err8;

	err = sw_pool_init(sw, &sw->mc_grp_pool, SW_TYPE_MC_GRP,
			    sw->attr.max_mcast_grp);
	if (err)
		goto err9;

	err = sw_pool_init(sw, &sw->mc_elem_pool, SW_TYPE_MC_ELEM,
			    sw->attr.max_total_mcast_qp_attach);
	if (err)
		goto err10;

	return 0;

err10:
	sw_pool_cleanup(&sw->mc_grp_pool);
err9:
	sw_pool_cleanup(&sw->mw_pool);
err8:
	sw_pool_cleanup(&sw->mr_pool);
err7:
	sw_pool_cleanup(&sw->cq_pool);
err6:
	sw_pool_cleanup(&sw->qp_pool);
err5:
	sw_pool_cleanup(&sw->srq_pool);
err4:
	sw_pool_cleanup(&sw->ah_pool);
err3:
	sw_pool_cleanup(&sw->pd_pool);
err2:
	sw_pool_cleanup(&sw->uc_pool);
err1:
	return err;
}

/* initialize sw device state */
int sw_init(struct sw_dev *sw)
{
	int err;

	/* init default device parameters */
	sw_init_device_param(sw);

	sw_init_ports(sw);

	err = sw_init_pools(sw);
	if (err)
		return err;

	/* init pending mmap list */
	spin_lock_init(&sw->mmap_offset_lock);
	spin_lock_init(&sw->pending_lock);
	INIT_LIST_HEAD(&sw->pending_mmaps);

	mutex_init(&sw->usdev_lock);

	return 0;
}

void sw_set_mtu(struct sw_dev *sw, unsigned int ndev_mtu)
{
	struct sw_port *port = &sw->port;
	enum ib_mtu mtu;

	mtu = eth_mtu_int_to_enum(ndev_mtu);

	/* Make sure that new MTU in range */
	mtu = mtu ? min_t(enum ib_mtu, mtu, IB_MTU_4096) : IB_MTU_256;

	port->attr.active_mtu = mtu;
	port->mtu_cap = ib_mtu_enum_to_int(mtu);
}
