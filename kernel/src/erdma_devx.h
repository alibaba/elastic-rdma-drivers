/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */

/* Authors: Cheng Xu <chengyou@linux.alibaba.com> */
/*          Kai Shen <kaishen@linux.alibaba.com> */
/* Copyright (c) 2020-2025, Alibaba Group. */

#ifndef __ERDMA_DEVX_H__
#define __ERDMA_DEVX_H__

#include <linux/kernel.h>

struct erdma_devx_create_object_cq_req {
	uint32_t umem_id;
	uint32_t depth;
	uint32_t eqn;
	uint32_t max_qbuf_len;
	uint32_t qbuf_offset;
	/* Dbrec config */
	uint32_t dbrec_umem_id;
	uint32_t dbrec_offset;
};

struct erdma_devx_create_object_qp_req {
	uint32_t wq_umem_id;
	uint32_t wq_offset;
	uint32_t wq_max_len;
	uint32_t pdn;
	uint32_t scqn;
	uint32_t rcqn;
	uint16_t sq_depth;
	uint16_t sq_wqe_size; /* num of wqebb */
	uint16_t rq_depth;
	uint16_t rq_wqe_size; /* num of wqebb */
	uint32_t dbrec_umem_id;
	uint32_t dbrec_offset;
};

struct erdmadv_devx_obj_create_param_in {
	union {
		struct erdma_devx_create_object_cq_req cq;
		struct erdma_devx_create_object_qp_req qp;
		uint32_t rsvd1[32];
	};
};

static_assert(sizeof(struct erdmadv_devx_obj_create_param_in) == 128, "erdmadv_devx_obj_create_param_in must be 128 bytes.");

struct erdmadv_devx_obj_create_param_out {
	uint32_t obj_id;
	uint32_t rsvd[7];
};

static_assert(sizeof(struct erdmadv_devx_obj_create_param_out) == 32, "erdmadv_devx_obj_create_param_out must be 32 bytes.");

enum erdma_devx_modify_object_qp_cmd {
	ERDMA_DEVX_OBJ_MODIFY_QP_OP_RST2INIT = 1,
	ERDMA_DEVX_OBJ_MODIFY_QP_OP_INIT2RTR = 2,
	ERDMA_DEVX_OBJ_MODIFY_QP_OP_RTR2RTS = 3,
};


struct erdma_devx_modify_object_qp_req {
	uint32_t op;
	uint32_t remote_qpn;
	uint32_t local_gid_index;
	uint32_t rsvd;
	__be64 dgid_subnet_prefix;
	__be64 dgid_interface_id;
	__be64 sgid_subnet_prefix;
	__be64 sgid_interface_id;
};

struct erdmadv_devx_obj_modify_param_in {
	union {
		struct erdma_devx_modify_object_qp_req qp;
		uint32_t rsvd1[32];
	};
};

static_assert(sizeof(struct erdmadv_devx_obj_modify_param_in) == 128,
	      "erdmadv_devx_obj_modify_param_in must be 128 bytes.");

struct erdmadv_devx_obj_modify_param_out {
	uint32_t rsvd[8];
};

static_assert(sizeof(struct erdmadv_devx_obj_modify_param_out) == 32,
	      "erdmadv_devx_obj_modify_param_out must be 32 bytes.");

#endif
