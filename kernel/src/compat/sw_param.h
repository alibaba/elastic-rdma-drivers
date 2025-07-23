/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
 * Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.
 */

#ifndef SW_PARAM_H
#define SW_PARAM_H

#include "rdma_user_sw.h"

static inline enum ib_mtu sw_mtu_int_to_enum(int mtu)
{
	if (mtu < 256)
		return 0;
	else if (mtu < 512)
		return IB_MTU_256;
	else if (mtu < 1024)
		return IB_MTU_512;
	else if (mtu < 2048)
		return IB_MTU_1024;
	else if (mtu < 4096)
		return IB_MTU_2048;
	else
		return IB_MTU_4096;
}

/* lack */
#ifndef SW_MAX_HDR_LENGTH
#define SW_MAX_HDR_LENGTH	(80)
#endif

/* Find the IB mtu for a given network MTU. */
static inline enum ib_mtu eth_mtu_int_to_enum(int mtu)
{
	mtu -= SW_MAX_HDR_LENGTH;

	return sw_mtu_int_to_enum(mtu);
}

/* default/initial sw device parameter settings */
enum sw_device_param {
	SW_MAX_MR_SIZE			= -1ull,
	SW_PAGE_SIZE_CAP		= 0xfffff000,
	SW_MAX_QP			= 0x10000,
	SW_MAX_QP_WR			= 0x4000,
	SW_DEVICE_CAP_FLAGS		= IB_DEVICE_BAD_PKEY_CNTR
					| IB_DEVICE_BAD_QKEY_CNTR
					| IB_DEVICE_AUTO_PATH_MIG
					| IB_DEVICE_CHANGE_PHY_PORT
					| IB_DEVICE_UD_AV_PORT_ENFORCE
					| IB_DEVICE_PORT_ACTIVE_EVENT
					| IB_DEVICE_SYS_IMAGE_GUID
					| IB_DEVICE_RC_RNR_NAK_GEN
					| IB_DEVICE_SRQ_RESIZE
					| IB_DEVICE_MEM_MGT_EXTENSIONS,
	SW_MAX_SGE			= 32,
	SW_MAX_WQE_SIZE		= sizeof(struct sw_send_wqe) +
					  sizeof(struct ib_sge) * SW_MAX_SGE,
	SW_MAX_INLINE_DATA		= SW_MAX_WQE_SIZE -
					  sizeof(struct sw_send_wqe),
	SW_MAX_SGE_RD			= 32,
	SW_MAX_CQ			= 16384,
	SW_MAX_LOG_CQE			= 15,
	SW_MAX_MR			= 256 * 1024,
	SW_MAX_PD			= 0x7ffc,
	SW_MAX_QP_RD_ATOM		= 128,
	SW_MAX_RES_RD_ATOM		= 0x3f000,
	SW_MAX_QP_INIT_RD_ATOM		= 128,
	SW_MAX_MCAST_GRP		= 8192,
	SW_MAX_MCAST_QP_ATTACH		= 56,
	SW_MAX_TOT_MCAST_QP_ATTACH	= 0x70000,
	SW_MAX_AH			= 100,
	SW_MAX_SRQ			= 960,
	SW_MAX_SRQ_WR			= 0x4000,
	SW_MIN_SRQ_WR			= 1,
	SW_MAX_SRQ_SGE			= 27,
	SW_MIN_SRQ_SGE			= 1,
	SW_MAX_FMR_PAGE_LIST_LEN	= 512,
	SW_MAX_PKEYS			= 1,
	SW_LOCAL_CA_ACK_DELAY		= 15,

	SW_MAX_UCONTEXT		= 512,

	SW_NUM_PORT			= 1,

	SW_MIN_QP_INDEX		= 16,
	SW_MAX_QP_INDEX		= 0x00020000,

	SW_MIN_SRQ_INDEX		= 0x00020001,
	SW_MAX_SRQ_INDEX		= 0x00040000,

	SW_MIN_MR_INDEX		= 0x00000001,
	SW_MAX_MR_INDEX		= 0x00040000,
	SW_MIN_MW_INDEX		= 0x00040001,
	SW_MAX_MW_INDEX		= 0x00060000,
	SW_MAX_PKT_PER_ACK		= 64,

	SW_MAX_UNACKED_PSNS		= 128,

	/* Max inflight SKBs per queue pair */
	SW_INFLIGHT_SKBS_PER_QP_HIGH	= 64,
	SW_INFLIGHT_SKBS_PER_QP_LOW	= 16,

	/* Delay before calling arbiter timer */
	SW_NSEC_ARB_TIMER_DELAY	= 200,

	/* IBTA v1.4 A3.3.1 VENDOR INFORMATION section */
	SW_VENDOR_ID			= 0XFFFFFF,
};

/* default/initial sw port parameters */
enum sw_port_param {
	SW_PORT_GID_TBL_LEN		= 1024,
	SW_PORT_PORT_CAP_FLAGS		= RDMA_CORE_CAP_PROT_ROCE_UDP_ENCAP,
	SW_PORT_MAX_MSG_SZ		= 0x800000,
	SW_PORT_BAD_PKEY_CNTR		= 0,
	SW_PORT_QKEY_VIOL_CNTR		= 0,
	SW_PORT_LID			= 0,
	SW_PORT_SM_LID			= 0,
	SW_PORT_SM_SL			= 0,
	SW_PORT_LMC			= 0,
	SW_PORT_MAX_VL_NUM		= 1,
	SW_PORT_SUBNET_TIMEOUT		= 0,
	SW_PORT_INIT_TYPE_REPLY	= 0,
	SW_PORT_ACTIVE_WIDTH		= IB_WIDTH_1X,
	SW_PORT_ACTIVE_SPEED		= 1,
	SW_PORT_PKEY_TBL_LEN		= 1,
	SW_PORT_SUBNET_PREFIX		= 0xfe80000000000000ULL,
};

/* default/initial port info parameters */
enum sw_port_info_param {
	SW_PORT_INFO_VL_CAP		= 4,	/* 1-8 */
	SW_PORT_INFO_MTU_CAP		= 5,	/* 4096 */
	SW_PORT_INFO_OPER_VL		= 1,	/* 1 */
};

#endif /* SW_PARAM_H */
