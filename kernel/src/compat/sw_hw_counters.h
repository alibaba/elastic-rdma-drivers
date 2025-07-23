/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * Copyright (c) 2017 Mellanox Technologies Ltd. All rights reserved.
 */

#ifndef SW_HW_COUNTERS_H
#define SW_HW_COUNTERS_H

/*
 * when adding counters to enum also add
 * them to sw_counter_name[] vector.
 */
enum sw_counters {
	SW_CNT_SENT_PKTS,
	SW_CNT_RCVD_PKTS,
	SW_CNT_DUP_REQ,
	SW_CNT_OUT_OF_SEQ_REQ,
	SW_CNT_RCV_RNR,
	SW_CNT_SND_RNR,
	SW_CNT_RCV_SEQ_ERR,
	SW_CNT_COMPLETER_SCHED,
	SW_CNT_RETRY_EXCEEDED,
	SW_CNT_RNR_RETRY_EXCEEDED,
	SW_CNT_COMP_RETRY,
	SW_CNT_SEND_ERR,
	SW_CNT_LINK_DOWNED,
	SW_CNT_RDMA_SEND,
	SW_CNT_RDMA_RECV,
	SW_NUM_OF_COUNTERS
};

struct rdma_hw_stats *sw_ib_alloc_hw_stats(struct ib_device *ibdev,
					    u8 port_num);
int sw_ib_get_hw_stats(struct ib_device *ibdev,
			struct rdma_hw_stats *stats,
			u8 port, int index);
#endif /* SW_HW_COUNTERS_H */
