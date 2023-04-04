// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB

/* Authors: Cheng Xu <chengyou@linux.alibaba.com> */
/*          Kai Shen <kaishen@linux.alibaba.com> */
/* Copyright (c) 2020-2022, Alibaba Group. */

#include "erdma.h"

#if defined(HAVE_SINGLE_HW_STATS) || defined(HAVE_SPLIT_STATS_ALLOC)

#ifndef HAVE_STAT_DESC_STRUCT
static const char *const erdma_stats_names[] = {
	[ERDMA_STATS_IW_LISTEN_CREATE] = "listen_create_cnt",
	[ERDMA_STATS_IW_LISTEN_IPV6] = "listen_ipv6_cnt",
	[ERDMA_STATS_IW_LISTEN_SUCCESS] = "listen_success_cnt",
	[ERDMA_STATS_IW_LISTEN_FAILED] = "listen_failed_cnt",
	[ERDMA_STATS_IW_LISTEN_DESTROY] = "listen_destroy_cnt",
	[ERDMA_STATS_IW_ACCEPT] = "accept_total_cnt",
	[ERDMA_STATS_IW_ACCEPT_SUCCESS] = "accept_success_cnt",
	[ERDMA_STATS_IW_ACCEPT_FAILED] = "accept_failed_cnt",
	[ERDMA_STATS_IW_REJECT] = "reject_cnt",
	[ERDMA_STATS_IW_REJECT_FAILED] = "reject_failed_cnt",
	[ERDMA_STATS_IW_CONNECT] = "connect_total_cnt",
	[ERDMA_STATS_IW_CONNECT_SUCCESS] = "connect_success_cnt",
	[ERDMA_STATS_IW_CONNECT_FAILED] = "connect_failed_cnt",
	[ERDMA_STATS_IW_CONNECT_TIMEOUT] = "connect_timeout_cnt",
	[ERDMA_STATS_IW_CONNECT_RST] = "connect_reset_cnt",
	[ERDMA_STATS_CMDQ_SUBMITTED] = "cmdq_submitted_cnt",
	[ERDMA_STATS_CMDQ_COMP] = "cmdq_comp_cnt",
	[ERDMA_STATS_CMDQ_EQ_NOTIFY] = "cmdq_eq_notify_cnt",
	[ERDMA_STATS_CMDQ_EQ_EVENT] = "cmdq_eq_event_cnt",
	[ERDMA_STATS_CMDQ_CQ_ARMED] = "cmdq_cq_armed_cnt",

	[ERDMA_STATS_AEQ_EVENT] = "erdma_aeq_event_cnt",
	[ERDMA_STATS_AEQ_NOTIFY] = "erdma_aeq_notify_cnt",

	[ERDMA_STATS_CMD_ALLOC_MR] = "verbs_alloc_mr_cnt",
	[ERDMA_STATS_CMD_ALLOC_MR_FAILED] = "verbs_alloc_mr_failed_cnt",
	[ERDMA_STATS_CMD_ALLOC_PD] = "verbs_alloc_pd_cnt",
	[ERDMA_STATS_CMD_ALLOC_PD_FAILED] = "verbs_alloc_pd_failed_cnt",
	[ERDMA_STATS_CMD_ALLOC_UCTX] = "verbs_alloc_uctx_cnt",
	[ERDMA_STATS_CMD_ALLOC_UCTX_FAILED] = "verbs_alloc_uctx_failed_cnt",

	[ERDMA_STATS_CMD_CREATE_CQ] = "verbs_create_cq_cnt",
	[ERDMA_STATS_CMD_CREATE_CQ_FAILED] = "verbs_create_cq_failed_cnt",
	[ERDMA_STATS_CMD_CREATE_QP] = "verbs_create_qp_cnt",
	[ERDMA_STATS_CMD_CREATE_QP_FAILED] = "verbs_create_qp_failed_cnt",

	[ERDMA_STATS_CMD_DESTROY_QP] = "verbs_create_qp_failed_cnt",
	[ERDMA_STATS_CMD_DESTROY_CQ] = "verbs_create_cq_failed_cnt",

	[ERDMA_STATS_CMD_DEALLOC_PD] = "verbs_dealloc_pd_cnt",
	[ERDMA_STATS_CMD_DEALLOC_UCTX] = "verbs_dealloc_uctx_cnt",
	[ERDMA_STATS_CMD_DEREG_MR] = "verbs_dereg_mr_cnt",
	[ERDMA_STATS_CMD_DEREG_MR_FAILED] = "verbs_dereg_mr_failed_cnt",
	[ERDMA_STATS_CMD_DESTROY_CQ] = "verbs_destroy_cq_cnt",
	[ERDMA_STATS_CMD_DESTROY_CQ_FAILED] = "verbs_destroy_cq_failed_cnt",
	[ERDMA_STATS_CMD_DESTROY_QP] = "verbs_destroy_qp_cnt",
	[ERDMA_STATS_CMD_DESTROY_QP_FAILED] = "verbs_destroy_qp_failed_cnt",

	[ERDMA_STATS_CMD_GET_DMA_MR] = "verbs_get_dma_mr_cnt",
	[ERDMA_STATS_CMD_GET_DMA_MR_FAILED] = "verbs_get_dma_mr_failed_cnt",
	[ERDMA_STATS_CMD_REG_USR_MR] = "verbs_reg_usr_mr_cnt",
	[ERDMA_STATS_CMD_REG_USR_MR_FAILED] = "verbs_reg_usr_mr_failed_cnt",

	[ERDMA_STATS_TX_REQS_CNT] = "hw_tx_reqs_cnt",
	[ERDMA_STATS_TX_PACKETS_CNT] = "hw_tx_packets_cnt",
	[ERDMA_STATS_TX_BYTES_CNT] = "hw_tx_bytes_cnt",
	[ERDMA_STATS_TX_DISABLE_DROP_CNT] = "hw_disable_drop_cnt",
	[ERDMA_STATS_TX_BPS_METER_DROP_CNT] = "hw_bps_limit_drop_cnt",
	[ERDMA_STATS_TX_PPS_METER_DROP_CNT] = "hw_pps_limit_drop_cnt",
	[ERDMA_STATS_RX_PACKETS_CNT] = "hw_rx_packets_cnt",
	[ERDMA_STATS_RX_BYTES_CNT] = "hw_rx_bytes_cnt",
	[ERDMA_STATS_RX_DISABLE_DROP_CNT] = "hw_rx_disable_drop_cnt",
	[ERDMA_STATS_RX_BPS_METER_DROP_CNT] = "hw_rx_bps_limit_drop_cnt",
	[ERDMA_STATS_RX_PPS_METER_DROP_CNT] = "hw_rx_pps_limit_drop_cnt",
};

#else

static const struct rdma_stat_desc erdma_hw_stat_descs[] = {
	[ERDMA_STATS_IW_LISTEN_CREATE].name = "listen_create_cnt",
	[ERDMA_STATS_IW_LISTEN_IPV6].name = "listen_ipv6_cnt",
	[ERDMA_STATS_IW_LISTEN_SUCCESS].name = "listen_success_cnt",
	[ERDMA_STATS_IW_LISTEN_FAILED].name = "listen_failed_cnt",
	[ERDMA_STATS_IW_LISTEN_DESTROY].name = "listen_destroy_cnt",
	[ERDMA_STATS_IW_ACCEPT].name = "accept_total_cnt",
	[ERDMA_STATS_IW_ACCEPT_SUCCESS].name = "accept_success_cnt",
	[ERDMA_STATS_IW_ACCEPT_FAILED].name = "accept_failed_cnt",
	[ERDMA_STATS_IW_REJECT].name = "reject_cnt",
	[ERDMA_STATS_IW_REJECT_FAILED].name = "reject_failed_cnt",
	[ERDMA_STATS_IW_CONNECT].name = "connect_total_cnt",
	[ERDMA_STATS_IW_CONNECT_SUCCESS].name = "connect_success_cnt",
	[ERDMA_STATS_IW_CONNECT_FAILED].name = "connect_failed_cnt",
	[ERDMA_STATS_IW_CONNECT_TIMEOUT].name = "connect_timeout_cnt",
	[ERDMA_STATS_IW_CONNECT_RST].name = "connect_reset_cnt",
	[ERDMA_STATS_CMDQ_SUBMITTED].name = "cmdq_submitted_cnt",
	[ERDMA_STATS_CMDQ_COMP].name = "cmdq_comp_cnt",
	[ERDMA_STATS_CMDQ_EQ_NOTIFY].name = "cmdq_eq_notify_cnt",
	[ERDMA_STATS_CMDQ_EQ_EVENT].name = "cmdq_eq_event_cnt",
	[ERDMA_STATS_CMDQ_CQ_ARMED].name = "cmdq_cq_armed_cnt",

	[ERDMA_STATS_AEQ_EVENT].name = "erdma_aeq_event_cnt",
	[ERDMA_STATS_AEQ_NOTIFY].name = "erdma_aeq_notify_cnt",

	[ERDMA_STATS_CMD_ALLOC_MR].name = "verbs_alloc_mr_cnt",
	[ERDMA_STATS_CMD_ALLOC_MR_FAILED].name = "verbs_alloc_mr_failed_cnt",
	[ERDMA_STATS_CMD_ALLOC_PD].name = "verbs_alloc_pd_cnt",
	[ERDMA_STATS_CMD_ALLOC_PD_FAILED].name = "verbs_alloc_pd_failed_cnt",
	[ERDMA_STATS_CMD_ALLOC_UCTX].name = "verbs_alloc_uctx_cnt",
	[ERDMA_STATS_CMD_ALLOC_UCTX_FAILED].name =
		"verbs_alloc_uctx_failed_cnt",

	[ERDMA_STATS_CMD_CREATE_CQ].name = "verbs_create_cq_cnt",
	[ERDMA_STATS_CMD_CREATE_CQ_FAILED].name = "verbs_create_cq_failed_cnt",
	[ERDMA_STATS_CMD_CREATE_QP].name = "verbs_create_qp_cnt",
	[ERDMA_STATS_CMD_CREATE_QP_FAILED].name = "verbs_create_qp_failed_cnt",

	[ERDMA_STATS_CMD_DESTROY_QP].name = "verbs_create_qp_failed_cnt",
	[ERDMA_STATS_CMD_DESTROY_CQ].name = "verbs_create_cq_failed_cnt",

	[ERDMA_STATS_CMD_DEALLOC_PD].name = "verbs_dealloc_pd_cnt",
	[ERDMA_STATS_CMD_DEALLOC_UCTX].name = "verbs_dealloc_uctx_cnt",
	[ERDMA_STATS_CMD_DEREG_MR].name = "verbs_dereg_mr_cnt",
	[ERDMA_STATS_CMD_DEREG_MR_FAILED].name = "verbs_dereg_mr_failed_cnt",
	[ERDMA_STATS_CMD_DESTROY_CQ].name = "verbs_destroy_cq_cnt",
	[ERDMA_STATS_CMD_DESTROY_CQ_FAILED].name =
		"verbs_destroy_cq_failed_cnt",
	[ERDMA_STATS_CMD_DESTROY_QP].name = "verbs_destroy_qp_cnt",
	[ERDMA_STATS_CMD_DESTROY_QP_FAILED].name =
		"verbs_destroy_qp_failed_cnt",

	[ERDMA_STATS_CMD_GET_DMA_MR].name = "verbs_get_dma_mr_cnt",
	[ERDMA_STATS_CMD_GET_DMA_MR_FAILED].name =
		"verbs_get_dma_mr_failed_cnt",
	[ERDMA_STATS_CMD_REG_USR_MR].name = "verbs_reg_usr_mr_cnt",
	[ERDMA_STATS_CMD_REG_USR_MR_FAILED].name =
		"verbs_reg_usr_mr_failed_cnt",

	[ERDMA_STATS_TX_REQS_CNT].name = "hw_tx_reqs_cnt",
	[ERDMA_STATS_TX_PACKETS_CNT].name = "hw_tx_packets_cnt",
	[ERDMA_STATS_TX_BYTES_CNT].name = "hw_tx_bytes_cnt",
	[ERDMA_STATS_TX_DISABLE_DROP_CNT].name = "hw_disable_drop_cnt",
	[ERDMA_STATS_TX_BPS_METER_DROP_CNT].name = "hw_bps_limit_drop_cnt",
	[ERDMA_STATS_TX_PPS_METER_DROP_CNT].name = "hw_pps_limit_drop_cnt",
	[ERDMA_STATS_RX_PACKETS_CNT].name = "hw_rx_packets_cnt",
	[ERDMA_STATS_RX_BYTES_CNT].name = "hw_rx_bytes_cnt",
	[ERDMA_STATS_RX_DISABLE_DROP_CNT].name = "hw_rx_disable_drop_cnt",
	[ERDMA_STATS_RX_BPS_METER_DROP_CNT].name = "hw_rx_bps_limit_drop_cnt",
	[ERDMA_STATS_RX_PPS_METER_DROP_CNT].name = "hw_rx_pps_limit_drop_cnt",

};

#endif

struct rdma_hw_stats *erdma_alloc_hw_stats(struct ib_device *ibdev,
					   port_t port_num)
{
#ifndef HAVE_STAT_DESC_STRUCT
	return rdma_alloc_hw_stats_struct(erdma_stats_names, ERDMA_STATS_MAX,
					  RDMA_HW_STATS_DEFAULT_LIFESPAN);
#else
	return rdma_alloc_hw_stats_struct(erdma_hw_stat_descs, ERDMA_STATS_MAX,
					  RDMA_HW_STATS_DEFAULT_LIFESPAN);
#endif
}

int erdma_get_hw_stats(struct ib_device *ibdev, struct rdma_hw_stats *stats,
		       port_t port_num, int index)
{
	struct erdma_dev *dev = to_edev(ibdev);

	atomic64_set(&dev->stats.value[ERDMA_STATS_CMDQ_SUBMITTED],
		     dev->cmdq.sq.total_cmds);
	atomic64_set(&dev->stats.value[ERDMA_STATS_CMDQ_COMP],
		     dev->cmdq.sq.total_comp_cmds);
	atomic64_set(&dev->stats.value[ERDMA_STATS_CMDQ_EQ_NOTIFY],
		     atomic64_read(&dev->cmdq.eq.notify_num));
	atomic64_set(&dev->stats.value[ERDMA_STATS_CMDQ_EQ_EVENT],
		     atomic64_read(&dev->cmdq.eq.event_num));
	atomic64_set(&dev->stats.value[ERDMA_STATS_CMDQ_CQ_ARMED],
		     atomic64_read(&dev->cmdq.cq.armed_num));
	atomic64_set(&dev->stats.value[ERDMA_STATS_AEQ_EVENT],
		     atomic64_read(&dev->aeq.event_num));
	atomic64_set(&dev->stats.value[ERDMA_STATS_AEQ_NOTIFY],
		     atomic64_read(&dev->aeq.notify_num));

	memcpy(&stats->value[0], &dev->stats.value[0],
	       sizeof(u64) * ERDMA_STATS_MAX);

	return stats->num_counters;
}
#endif
