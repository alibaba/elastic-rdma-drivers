/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR Linux-OpenIB) */
/*
 * Copyright (c) 2020-2022, Alibaba Group.
 */

#ifndef __ERDMA_USER_H__
#define __ERDMA_USER_H__

#include <linux/types.h>
#include <rdma/ib_user_ioctl_cmds.h>

#define ERDMA_ABI_VERSION       1

struct erdma_ureq_create_cq {
	__aligned_u64 db_record_va;
	__aligned_u64 qbuf_va;
	__u32 qbuf_len;
	__u32 rsvd0;
};

enum {
	ERDMA_ALLOC_PD_CMD_COMP_PDN = 1 << 0,
};

struct erdma_uresp_alloc_pd {
	__u32 comp_mask;
	__u32 pdn;
	__u32 rsvd[2];
};

struct erdma_uresp_create_cq {
	__u32 cq_id;
	__u32 num_cqe;
};

struct erdma_ureq_create_qp {
	__aligned_u64 db_record_va;
	__aligned_u64 qbuf_va;
	__u32 qbuf_len;
	__u32 rsvd0;
};

struct erdma_uresp_create_qp {
	__u32 qp_id;
	__u32 num_sqe;
	__u32 num_rqe;
	__u32 rq_offset;
};

struct erdma_uresp_alloc_ctx {
	__u32 dev_id;
	__u32 pad;
	__u32 sdb_type;
	__u32 sdb_entid;
	__aligned_u64 sdb;
	__aligned_u64 rdb;
	__aligned_u64 cdb;
	__u32 sdb_off;
	__u32 rdb_off;
	__u32 cdb_off;
};

enum erdma_objects {
	ERDMA_OBJECT_DEVX = (1U << UVERBS_ID_NS_SHIFT),
	ERDMA_OBJECT_DEVX_OBJ,
	ERDMA_OBJECT_DEVX_UMEM,
};

enum erdma_devx_methods {
	ERDMA_METHOD_DEVX_OTHER = (1U << UVERBS_ID_NS_SHIFT),
};

enum erdma_devx_other_attrs {
	ERDMA_ATTR_DEVX_OTHER_CMD_IN = (1U << UVERBS_ID_NS_SHIFT),
	ERDMA_ATTR_DEVX_OTHER_CMD_OUT,
};

// DEVX OBJ METHODS and their ATTRS
enum erdma_devx_obj_methods {
	ERDMA_METHOD_DEVX_OBJ_CREATE = (1U << UVERBS_ID_NS_SHIFT),
	ERDMA_METHOD_DEVX_OBJ_DESTROY,
	ERDMA_METHOD_DEVX_OBJ_MODIFY,
	ERDMA_METHOD_DEVX_OBJ_QUERY,
	ERDMA_METHOD_DEVX_OBJ_ASYNC_QUERY,
};

enum {
	ERDMA_DEVX_OBJ_TYPE_CQ = 1,
	ERDMA_DEVX_OBJ_TYPE_QP = 2,
};

enum erdma_devx_obj_create_attrs {
	ERDMA_ATTR_DEVX_OBJ_CREATE_HANDLE = (1U << UVERBS_ID_NS_SHIFT),
	ERDMA_ATTR_DEVX_OBJ_CREATE_TYPE,
	ERDMA_ATTR_DEVX_OBJ_CREATE_CMD_IN,
	ERDMA_ATTR_DEVX_OBJ_CREATE_CMD_OUT,
};

enum erdma_devx_obj_modify_attrs {
	ERDMA_ATTR_DEVX_OBJ_MODIFY_HANDLE = (1U << UVERBS_ID_NS_SHIFT),
	ERDMA_ATTR_DEVX_OBJ_MODIFY_TYPE,
	ERDMA_ATTR_DEVX_OBJ_MODIFY_CMD_IN,
	ERDMA_ATTR_DEVX_OBJ_MODIFY_CMD_OUT,
};

enum erdma_devx_obj_destroy_attrs {
	ERDMA_ATTR_DEVX_OBJ_DESTROY_HANDLE = (1U << UVERBS_ID_NS_SHIFT),
};

enum erdma_devx_umem_methods {
	ERDMA_METHOD_DEVX_UMEM_REG = (1U << UVERBS_ID_NS_SHIFT),
	ERDMA_METHOD_DEVX_UMEM_DEREG,
};

enum erdma_devx_umem_reg_attrs {
	ERDMA_ATTR_DEVX_UMEM_REG_HANDLE = (1U << UVERBS_ID_NS_SHIFT),
	ERDMA_ATTR_DEVX_UMEM_REG_ADDR,
	ERDMA_ATTR_DEVX_UMEM_REG_LEN,
	ERDMA_ATTR_DEVX_UMEM_REG_ACCESS,
	ERDMA_ATTR_DEVX_UMEM_REG_OUT_ID,
	ERDMA_ATTR_DEVX_UMEM_REG_PGSZ_BITMAP,
	ERDMA_ATTR_DEVX_UMEM_REG_DMABUF_FD,
};

enum erdma_devx_umem_dereg_attrs {
	ERDMA_ATTR_DEVX_UMEM_DEREG_HANDLE = (1U << UVERBS_ID_NS_SHIFT),
};

struct erdma_ureq_modify_qp {
	__u8 sq_flush;
	__u8 rq_flush;
	__u8 rsvd[6];
	__u16 sq_pi;
	__u16 rq_pi;
	__u8 rsvd1[4];
};

#endif
