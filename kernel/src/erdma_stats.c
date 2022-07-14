// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB

/* Authors: Cheng Xu <chengyou@linux.alibaba.com> */
/*          Kai Shen <kaishen@linux.alibaba.com> */
/* Copyright (c) 2020-2022, Alibaba Group. */

#include "erdma.h"

static const char * const erdma_stats_names[] = {
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

};

struct rdma_hw_stats *erdma_alloc_hw_stats(struct ib_device *ibdev, port_t port_num)
{
	return rdma_alloc_hw_stats_struct(erdma_stats_names,
			ERDMA_STATS_MAX, RDMA_HW_STATS_DEFAULT_LIFESPAN);
}

int erdma_get_hw_stats(struct ib_device *ibdev,
	struct rdma_hw_stats *stats, port_t port_num, int index)
{
	struct erdma_dev *dev = to_edev(ibdev);

	atomic64_set(&dev->stats.value[ERDMA_STATS_CMDQ_SUBMITTED], dev->cmdq.sq.total_cmds);
	atomic64_set(&dev->stats.value[ERDMA_STATS_CMDQ_COMP], dev->cmdq.sq.total_comp_cmds);
	atomic64_set(&dev->stats.value[ERDMA_STATS_CMDQ_EQ_NOTIFY],
			atomic64_read(&dev->cmdq.eq.notify_num));
	atomic64_set(&dev->stats.value[ERDMA_STATS_CMDQ_EQ_EVENT],
			atomic64_read(&dev->cmdq.eq.event_num));
	atomic64_set(&dev->stats.value[ERDMA_STATS_CMDQ_CQ_ARMED],
			atomic64_read(&dev->cmdq.cq.armed_num));
	atomic64_set(&dev->stats.value[ERDMA_STATS_AEQ_EVENT], atomic64_read(&dev->aeq.event_num));
	atomic64_set(&dev->stats.value[ERDMA_STATS_AEQ_NOTIFY],
			atomic64_read(&dev->aeq.notify_num));

	memcpy(&stats->value[0], &dev->stats.value[0], sizeof(u64) * ERDMA_STATS_MAX);

	return stats->num_counters;
}
