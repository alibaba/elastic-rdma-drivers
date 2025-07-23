/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */

/* Authors: Cheng Xu <chengyou@linux.alibaba.com> */
/*          Kai Shen <kaishen@linux.alibaba.com> */
/* Copyright (c) 2020-2022, Alibaba Group. */

#ifndef __ERDMA_HW_H__
#define __ERDMA_HW_H__

#include <linux/kernel.h>
#include <linux/types.h>

/* PCIe device related definition. */
#define PCI_VENDOR_ID_ALIBABA 0x1ded

#define ERDMA_PCI_WIDTH 64
#define ERDMA_FUNC_BAR 0
#define ERDMA_MISX_BAR 2

#define ERDMA_BAR_MASK (BIT(ERDMA_FUNC_BAR) | BIT(ERDMA_MISX_BAR))

/* MSI-X related. */
#define ERDMA_NUM_MSIX_VEC 32U
#define ERDMA_MSIX_VECTOR_CMDQ 0

/* PCIe Bar0 Registers. */
#define ERDMA_REGS_VERSION_REG 0x0
#define ERDMA_REGS_DEV_CTRL_REG 0x10
#define ERDMA_REGS_DEV_ST_REG 0x14
#define ERDMA_REGS_NETDEV_MAC_L_REG 0x18
#define ERDMA_REGS_NETDEV_MAC_H_REG 0x1C
#define ERDMA_REGS_CMDQ_SQ_ADDR_L_REG 0x20
#define ERDMA_REGS_CMDQ_SQ_ADDR_H_REG 0x24
#define ERDMA_REGS_CMDQ_CQ_ADDR_L_REG 0x28
#define ERDMA_REGS_CMDQ_CQ_ADDR_H_REG 0x2C
#define ERDMA_REGS_CMDQ_DEPTH_REG 0x30
#define ERDMA_REGS_CMDQ_EQ_DEPTH_REG 0x34
#define ERDMA_REGS_CMDQ_EQ_ADDR_L_REG 0x38
#define ERDMA_REGS_CMDQ_EQ_ADDR_H_REG 0x3C
#define ERDMA_REGS_AEQ_ADDR_L_REG 0x40
#define ERDMA_REGS_AEQ_ADDR_H_REG 0x44
#define ERDMA_REGS_AEQ_DEPTH_REG 0x48
#define ERDMA_REGS_GRP_NUM_REG 0x4c
#define ERDMA_REGS_AEQ_DB_REG 0x50
#define ERDMA_CMDQ_SQ_DB_HOST_ADDR_REG 0x60
#define ERDMA_CMDQ_CQ_DB_HOST_ADDR_REG 0x68
#define ERDMA_CMDQ_EQ_DB_HOST_ADDR_REG 0x70
#define ERDMA_AEQ_DB_HOST_ADDR_REG 0x78
#define ERDMA_REGS_CEQ_DB_BASE_REG 0x100
#define ERDMA_CMDQ_SQDB_REG 0x200
#define ERDMA_CMDQ_CQDB_REG 0x300

/* DEV_CTRL_REG details. */
#define ERDMA_REG_DEV_CTRL_RESET_MASK 0x00000001
#define ERDMA_REG_DEV_CTRL_INIT_MASK 0x00000002

/* DEV_ST_REG details. */
#define ERDMA_REG_DEV_ST_RESET_DONE_MASK 0x00000001U
#define ERDMA_REG_DEV_ST_INIT_DONE_MASK 0x00000002U

/* eRDMA PCIe DBs definition. */
#define ERDMA_BAR_DB_SPACE_BASE 4096

#define ERDMA_BAR_SQDB_SPACE_OFFSET ERDMA_BAR_DB_SPACE_BASE
#define ERDMA_BAR_SQDB_SPACE_SIZE (384 * 1024)

#define ERDMA_BAR_RQDB_SPACE_OFFSET \
	(ERDMA_BAR_SQDB_SPACE_OFFSET + ERDMA_BAR_SQDB_SPACE_SIZE)
#define ERDMA_BAR_RQDB_SPACE_SIZE (96 * 1024)

#define ERDMA_BAR_CQDB_SPACE_OFFSET \
	(ERDMA_BAR_RQDB_SPACE_OFFSET + ERDMA_BAR_RQDB_SPACE_SIZE)

/* Doorbell page resources related. */
/*
 * Max # of parallelly issued directSQE is 3072 per device,
 * hardware organizes this into 24 group, per group has 128 credits.
 */
#define ERDMA_DWQE_MAX_GRP_CNT 24
#define ERDMA_DWQE_NUM_PER_GRP 128

#define ERDMA_DWQE_TYPE0_CNT 64
#define ERDMA_DWQE_TYPE1_CNT 496
/* type1 DB contains 2 DBs, takes 256Byte. */
#define ERDMA_DWQE_TYPE1_CNT_PER_PAGE 16

#define ERDMA_SDB_SHARED_PAGE_INDEX 95

/* Doorbell related. */
#define ERDMA_DB_SIZE 8

#define ERDMA_CQDB_IDX_MASK GENMASK_ULL(63, 56)
#define ERDMA_CQDB_CQN_MASK GENMASK_ULL(55, 32)
#define ERDMA_CQDB_ARM_MASK BIT_ULL(31)
#define ERDMA_CQDB_SOL_MASK BIT_ULL(30)
#define ERDMA_CQDB_CMDSN_MASK GENMASK_ULL(29, 28)
#define ERDMA_CQDB_CI_MASK GENMASK_ULL(23, 0)

#define ERDMA_EQDB_ARM_MASK BIT(31)
#define ERDMA_EQDB_CI_MASK GENMASK_ULL(23, 0)

#define ERDMA_PAGE_SIZE_SUPPORT 0x7FFFF000

/* Hardware page size definition */
#define ERDMA_HW_PAGE_SHIFT 12
#define ERDMA_HW_PAGE_SIZE 4096

/* WQE related. */
#define EQE_SIZE 16
#define EQE_SHIFT 4
#define RQE_SIZE 32
#define RQE_SHIFT 5
#define CQE_SIZE 32
#define CQE_SHIFT 5
#define SQEBB_SIZE 32
#define SQEBB_SHIFT 5
#define SQEBB_MASK (~(SQEBB_SIZE - 1))
#define SQEBB_ALIGN(size) ((size + SQEBB_SIZE - 1) & SQEBB_MASK)
#define SQEBB_COUNT(size) (SQEBB_ALIGN(size) >> SQEBB_SHIFT)

#define ERDMA_MAX_SQE_SIZE 128
#define ERDMA_MAX_WQEBB_PER_SQE 4

/* CMDQ related. */
#define ERDMA_CMDQ_MAX_OUTSTANDING 128
#define ERDMA_CMDQ_SQE_SIZE 128

/* cmdq sub module definition. */
enum CMDQ_WQE_SUB_MOD {
	CMDQ_SUBMOD_RDMA = 0,
	CMDQ_SUBMOD_COMMON = 1
};

enum CMDQ_RDMA_OPCODE {
	CMDQ_OPCODE_QUERY_DEVICE = 0,
	CMDQ_OPCODE_CREATE_QP = 1,
	CMDQ_OPCODE_DESTROY_QP = 2,
	CMDQ_OPCODE_MODIFY_QP = 3,
	CMDQ_OPCODE_CREATE_CQ = 4,
	CMDQ_OPCODE_DESTROY_CQ = 5,
	CMDQ_OPCODE_REFLUSH = 6,
	CMDQ_OPCODE_REG_MR = 8,
	CMDQ_OPCODE_DEREG_MR = 9,
	CMDQ_OPCODE_QUERY_QPC = 11,
	CMDQ_OPCODE_QUERY_CQC = 12,
};

enum CMDQ_COMMON_OPCODE {
	CMDQ_OPCODE_CREATE_EQ = 0,
	CMDQ_OPCODE_DESTROY_EQ = 1,
	CMDQ_OPCODE_QUERY_FW_INFO = 2,
	CMDQ_OPCODE_CONF_MTU = 3,
	CMDQ_OPCODE_GET_STATS = 4,
	CMDQ_OPCODE_QUERY_EQC = 6,
	CMDQ_OPCODE_SET_RETRANS_NUM = 7,

	CMDQ_OPCODE_SET_EXT_ATTR = 10,
	CMDQ_OPCODE_GET_EXT_ATTR = 11,
};

/* cmdq-SQE HDR */
#define ERDMA_CMD_HDR_WQEBB_CNT_MASK GENMASK_ULL(54, 52)
#define ERDMA_CMD_HDR_CONTEXT_COOKIE_MASK GENMASK_ULL(47, 32)
#define ERDMA_CMD_HDR_SUB_MOD_MASK GENMASK_ULL(25, 24)
#define ERDMA_CMD_HDR_OPCODE_MASK GENMASK_ULL(23, 16)
#define ERDMA_CMD_HDR_WQEBB_INDEX_MASK GENMASK_ULL(15, 0)

struct erdma_cmdq_destroy_cq_req {
	u64 hdr;
	u32 cqn;
};

#define ERDMA_EQ_TYPE_AEQ 0
#define ERDMA_EQ_TYPE_CEQ 1

struct erdma_cmdq_create_eq_req {
	u64 hdr;
	u64 qbuf_addr;
	u8 vector_idx;
	u8 eqn;
	u8 depth;
	u8 qtype;
	u32 db_dma_addr_l;
	u32 db_dma_addr_h;
};

struct erdma_cmdq_destroy_eq_req {
	u64 hdr;
	u64 rsvd0;
	u8 vector_idx;
	u8 eqn;
	u8 rsvd1;
	u8 qtype;
};

struct erdma_cmdq_config_mtu_req {
	u64 hdr;
	u32 mtu;
};

struct erdma_cmdq_set_retrans_num_req {
	u64 hdr;
	u32 retrans_num;
};

#define ERDMA_EXT_ATTR_DACK_COUNT_MASK BIT(0)
#define ERDMA_EXT_ATTR_LEGACY_MODE_MASK BIT(2)
struct erdma_ext_attr {
	u32 attr_mask;
	u8 dack_count;
	u8 enable;
};

struct erdma_cmdq_set_ext_attr_req {
	u64 hdr;
	struct erdma_ext_attr attr;
};

/* create_cq cfg0 */
#define ERDMA_CMD_CREATE_CQ_DEPTH_MASK GENMASK(31, 24)
#define ERDMA_CMD_CREATE_CQ_PAGESIZE_MASK GENMASK(23, 20)
#define ERDMA_CMD_CREATE_CQ_CQN_MASK GENMASK(19, 0)

/* create_cq cfg1 */
#define ERDMA_CMD_CREATE_CQ_MTT_CNT_MASK GENMASK(31, 16)
#define ERDMA_CMD_CREATE_CQ_MTT_TYPE_MASK BIT(15)
#define ERDMA_CMD_CREATE_CQ_EQN_MASK GENMASK(9, 0)

struct erdma_cmdq_create_cq_req {
	u64 hdr;
	u32 cfg0;
	u32 qbuf_addr_l;
	u32 qbuf_addr_h;
	u32 cfg1;
	u64 cq_db_info_addr;
	u32 first_page_offset;
};

/* regmr/deregmr cfg0 */
#define ERDMA_CMD_MR_VALID_MASK BIT(31)
#define ERDMA_CMD_MR_VERSION_MASK GENMASK(30, 28)
#define ERDMA_CMD_MR_KEY_MASK GENMASK(27, 20)
#define ERDMA_CMD_MR_MPT_IDX_MASK GENMASK(19, 0)

/* regmr cfg1 */
#define ERDMA_CMD_REGMR_PD_MASK GENMASK(31, 12)
#define ERDMA_CMD_REGMR_TYPE_MASK GENMASK(7, 6)
#define ERDMA_CMD_REGMR_RIGHT_MASK GENMASK(5, 1)

/* regmr cfg2 */
#define ERDMA_CMD_REGMR_PAGESIZE_MASK GENMASK(31, 27)
#define ERDMA_CMD_REGMR_PBL_PAGESIZE_MASK GENMASK(26, 24)
#define ERDMA_CMD_REGMR_MTT_TYPE_MASK GENMASK(21, 20)
#define ERDMA_CMD_REGMR_MTT_CNT_MASK GENMASK(19, 0)

struct erdma_cmdq_reg_mr_req {
	u64 hdr;
	u32 cfg0;
	u32 cfg1;
	u64 start_va;
	u32 size;
	u32 cfg2;
	union {
		u64 phy_addr[4];
		struct {
			u64 rsvd;
			u32 size_h;
			u32 mtt_cnt_h;
		};
	};
};

struct erdma_cmdq_dereg_mr_req {
	u64 hdr;
	u32 cfg;
};

/* modify qp cfg */
#define ERDMA_CMD_MODIFY_QP_STATE_MASK GENMASK(31, 24)
#define ERDMA_CMD_MODIFY_QP_CC_MASK GENMASK(23, 20)
#define ERDMA_CMD_MODIFY_QP_QPN_MASK GENMASK(19, 0)

#define ERDMA_CMD_MODIFY_QP_IPV6_MASK BIT(31)
#define ERDMA_CMD_MODIFY_QP_WWI_PERF_MASK BIT(30)
#define ERDMA_CMD_MODIFY_QP_RQPN_MASK GENMASK(19, 0)

struct erdma_cmdq_modify_qp_req {
	u64 hdr;
	u32 cfg;
	u32 cookie;
	__be32 dip;
	__be32 sip;
	__be16 sport;
	__be16 dport;
	u32 send_nxt;
	u32 recv_nxt;
	u32 rsvd0;
	u32 rsvd1;
	__be32 flow_label;
	u8 ipv6_daddr[16];
	u8 ipv6_saddr[16];
};

/* create qp cfg0 */
#define ERDMA_CMD_CREATE_QP_SQ_DEPTH_MASK GENMASK(31, 20)
#define ERDMA_CMD_CREATE_QP_QPN_MASK GENMASK(19, 0)

/* create qp cfg1 */
#define ERDMA_CMD_CREATE_QP_RQ_DEPTH_MASK GENMASK(31, 20)
#define ERDMA_CMD_CREATE_QP_PD_MASK GENMASK(19, 0)

/* create qp cqn_mtt_cfg */
#define ERDMA_CMD_CREATE_QP_PAGE_SIZE_MASK GENMASK(31, 28)
#define ERDMA_CMD_CREATE_QP_CQN_MASK GENMASK(23, 0)

/* create qp mtt_cfg */
#define ERDMA_CMD_CREATE_QP_PAGE_OFFSET_MASK GENMASK(31, 12)
#define ERDMA_CMD_CREATE_QP_MTT_CNT_MASK GENMASK(11, 1)
#define ERDMA_CMD_CREATE_QP_MTT_TYPE_MASK BIT(0)

#define ERDMA_CMDQ_CREATE_QP_RESP_COOKIE_MASK GENMASK_ULL(31, 0)

struct erdma_cmdq_create_qp_req {
	u64 hdr;
	u32 cfg0;
	u32 cfg1;
	u32 sq_cqn_mtt_cfg;
	u32 rq_cqn_mtt_cfg;
	u64 sq_buf_addr;
	u64 rq_buf_addr;
	u32 sq_mtt_cfg;
	u32 rq_mtt_cfg;
	u64 sq_db_info_dma_addr;
	u64 rq_db_info_dma_addr;

	u64 sq_mtt_entry[3];
	u64 rq_mtt_entry[3];
};

struct erdma_cmdq_destroy_qp_req {
	u64 hdr;
	u32 qpn;
};

struct erdma_cmdq_reflush_req {
	u64 hdr;
	u32 qpn;
	u32 sq_pi;
	u32 rq_pi;
};

/* cap qword 0 definition */
#define ERDMA_CMD_DEV_CAP_MAX_CQE_MASK GENMASK_ULL(47, 40)
#define ERDMA_CMD_DEV_CAP_FLAGS_MASK GENMASK_ULL(31, 24)
#define ERDMA_CMD_DEV_CAP_MAX_RECV_WR_MASK GENMASK_ULL(23, 16)
#define ERDMA_CMD_DEV_CAP_MAX_MR_SIZE_MASK GENMASK_ULL(7, 0)

/* cap qword 1 definition */
#define ERDMA_CMD_DEV_CAP_DMA_LOCAL_KEY_MASK GENMASK_ULL(63, 32)
#define ERDMA_CMD_DEV_CAP_DEFAULT_CC_MASK GENMASK_ULL(31, 28)
#define ERDMA_CMD_DEV_CAP_QBLOCK_MASK GENMASK_ULL(27, 16)
#define ERDMA_CMD_DEV_CAP_MAX_MW_MASK GENMASK_ULL(7, 0)

#define ERDMA_NQP_PER_QBLOCK 1024

enum {
	ERDMA_DEV_CAP_FLAGS_ATOMIC = 1 << 7,
	ERDMA_DEV_CAP_FLAGS_QUERY_QC = 1 << 6,
	ERDMA_DEV_CAP_FLAGS_MTT_VA = 1 << 5,
	ERDMA_DEV_CAP_FLAGS_IPV6 = 1 << 4,
};

#define ERDMA_CMD_INFO0_FW_VER_MASK GENMASK_ULL(31, 0)

/* CQE hdr */
#define ERDMA_CQE_HDR_OWNER_MASK BIT(31)
#define ERDMA_CQE_HDR_OPCODE_MASK GENMASK(23, 16)
#define ERDMA_CQE_HDR_QTYPE_MASK GENMASK(15, 8)
#define ERDMA_CQE_HDR_SYNDROME_MASK GENMASK(7, 0)

#define ERDMA_CQE_QTYPE_SQ 0
#define ERDMA_CQE_QTYPE_RQ 1
#define ERDMA_CQE_QTYPE_CMDQ 2

struct erdma_cqe {
	__be32 hdr;
	__be32 qe_idx;
	__be32 qpn;
	union {
		__le32 imm_data;
		__be32 inv_rkey;
	};
	__be32 size;
	__be32 rsvd[3];
};

struct erdma_sge {
	__aligned_le64 addr;
	__le32 length;
	__le32 key;
};

/* Receive Queue Element */
struct erdma_rqe {
	__le16 qe_idx;
	__le16 rsvd0;
	__le32 qpn;
	__le32 rsvd1;
	__le32 rsvd2;
	__le64 to;
	__le32 length;
	__le32 stag;
};

/* SQE */
#define ERDMA_SQE_HDR_SGL_LEN_MASK GENMASK_ULL(63, 56)
#define ERDMA_SQE_HDR_WQEBB_CNT_MASK GENMASK_ULL(54, 52)
#define ERDMA_SQE_HDR_QPN_MASK GENMASK_ULL(51, 32)
#define ERDMA_SQE_HDR_OPCODE_MASK GENMASK_ULL(31, 27)
#define ERDMA_SQE_HDR_DWQE_MASK BIT_ULL(26)
#define ERDMA_SQE_HDR_INLINE_MASK BIT_ULL(25)
#define ERDMA_SQE_HDR_FENCE_MASK BIT_ULL(24)
#define ERDMA_SQE_HDR_SE_MASK BIT_ULL(23)
#define ERDMA_SQE_HDR_CE_MASK BIT_ULL(22)
#define ERDMA_SQE_HDR_WQEBB_INDEX_MASK GENMASK_ULL(15, 0)

/* REG MR attrs */
#define ERDMA_SQE_MR_PGSZ_AVAIL_MASK BIT_ULL(0)
#define ERDMA_SQE_MR_ACCESS_MASK GENMASK(5, 1)
#define ERDMA_SQE_MR_MTT_TYPE_MASK GENMASK(7, 6)
#define ERDMA_SQE_MR_MTT_CNT_MASK GENMASK(31, 12)
#define ERDMA_SQE_MR_PGSZ_MASK GENMASK(4, 0)

struct erdma_write_sqe {
	__le64 hdr;
	__be32 imm_data;
	__le32 length;

	__le32 sink_stag;
	__le32 sink_to_l;
	__le32 sink_to_h;

	__le32 rsvd;

	struct erdma_sge sgl[];
};

struct erdma_send_sqe {
	__le64 hdr;
	union {
		__be32 imm_data;
		__le32 invalid_stag;
	};

	__le32 length;
	struct erdma_sge sgl[];
};

struct erdma_readreq_sqe {
	__le64 hdr;
	__le32 invalid_stag;
	__le32 length;
	__le32 sink_stag;
	__le32 sink_to_l;
	__le32 sink_to_h;
	__le32 rsvd;
};

struct erdma_atomic_sqe {
	__le64 hdr;
	__le64 rsvd;
	__le64 fetchadd_swap_data;
	__le64 cmp_data;

	struct erdma_sge remote;
	struct erdma_sge sgl;
};

struct erdma_reg_mr_sqe {
	__le64 hdr;
	__le64 addr;
	__le32 length;
	__le32 stag;
	__le32 attr0;
	__le32 attr1;
};

/* EQ related. */
#define ERDMA_DEFAULT_EQ_DEPTH 4096

/* ceqe */
#define ERDMA_CEQE_HDR_DB_MASK BIT_ULL(63)
#define ERDMA_CEQE_HDR_PI_MASK GENMASK_ULL(55, 32)
#define ERDMA_CEQE_HDR_O_MASK BIT_ULL(31)
#define ERDMA_CEQE_HDR_CQN_MASK GENMASK_ULL(19, 0)

/* aeqe */
#define ERDMA_AEQE_HDR_O_MASK BIT(31)
#define ERDMA_AEQE_HDR_TYPE_MASK GENMASK(23, 16)
#define ERDMA_AEQE_HDR_SUBTYPE_MASK GENMASK(7, 0)

#define ERDMA_AE_TYPE_QP_FATAL_EVENT 0
#define ERDMA_AE_TYPE_QP_ERQ_ERR_EVENT 1
#define ERDMA_AE_TYPE_ACC_ERR_EVENT 2
#define ERDMA_AE_TYPE_CQ_ERR 3
#define ERDMA_AE_TYPE_OTHER_ERROR 4

struct erdma_aeqe {
	__le32 hdr;
	__le32 event_data0;
	__le32 event_data1;
	__le32 rsvd;
};

enum erdma_opcode {
	ERDMA_OP_WRITE = 0,
	ERDMA_OP_READ = 1,
	ERDMA_OP_SEND = 2,
	ERDMA_OP_SEND_WITH_IMM = 3,

	ERDMA_OP_RECEIVE = 4,
	ERDMA_OP_RECV_IMM = 5,
	ERDMA_OP_RECV_INV = 6,

	ERDMA_OP_RSVD0 = 7,
	ERDMA_OP_RSVD1 = 8,
	ERDMA_OP_WRITE_WITH_IMM = 9,

	ERDMA_OP_RSVD2 = 10,
	ERDMA_OP_RSVD3 = 11,

	ERDMA_OP_RSP_SEND_IMM = 12,
	ERDMA_OP_SEND_WITH_INV = 13,

	ERDMA_OP_REG_MR = 14,
	ERDMA_OP_LOCAL_INV = 15,
	ERDMA_OP_READ_WITH_INV = 16,
	ERDMA_OP_ATOMIC_CAS = 17,
	ERDMA_OP_ATOMIC_FAA = 18,
	ERDMA_NUM_OPCODES = 19,
	ERDMA_OP_INVALID = ERDMA_NUM_OPCODES + 1
};

enum erdma_wc_status {
	ERDMA_WC_SUCCESS = 0,
	ERDMA_WC_GENERAL_ERR = 1,
	ERDMA_WC_RECV_WQE_FORMAT_ERR = 2,
	ERDMA_WC_RECV_STAG_INVALID_ERR = 3,
	ERDMA_WC_RECV_ADDR_VIOLATION_ERR = 4,
	ERDMA_WC_RECV_RIGHT_VIOLATION_ERR = 5,
	ERDMA_WC_RECV_PDID_ERR = 6,
	ERDMA_WC_RECV_WARRPING_ERR = 7,
	ERDMA_WC_SEND_WQE_FORMAT_ERR = 8,
	ERDMA_WC_SEND_WQE_ORD_EXCEED = 9,
	ERDMA_WC_SEND_STAG_INVALID_ERR = 10,
	ERDMA_WC_SEND_ADDR_VIOLATION_ERR = 11,
	ERDMA_WC_SEND_RIGHT_VIOLATION_ERR = 12,
	ERDMA_WC_SEND_PDID_ERR = 13,
	ERDMA_WC_SEND_WARRPING_ERR = 14,
	ERDMA_WC_FLUSH_ERR = 15,
	ERDMA_WC_RETRY_EXC_ERR = 16,
	ERDMA_NUM_WC_STATUS
};

enum erdma_vendor_err {
	ERDMA_WC_VENDOR_NO_ERR = 0,
	ERDMA_WC_VENDOR_INVALID_RQE = 1,
	ERDMA_WC_VENDOR_RQE_INVALID_STAG = 2,
	ERDMA_WC_VENDOR_RQE_ADDR_VIOLATION = 3,
	ERDMA_WC_VENDOR_RQE_ACCESS_RIGHT_ERR = 4,
	ERDMA_WC_VENDOR_RQE_INVALID_PD = 5,
	ERDMA_WC_VENDOR_RQE_WRAP_ERR = 6,
	ERDMA_WC_VENDOR_INVALID_SQE = 0x20,
	ERDMA_WC_VENDOR_ZERO_ORD = 0x21,
	ERDMA_WC_VENDOR_SQE_INVALID_STAG = 0x30,
	ERDMA_WC_VENDOR_SQE_ADDR_VIOLATION = 0x31,
	ERDMA_WC_VENDOR_SQE_ACCESS_ERR = 0x32,
	ERDMA_WC_VENDOR_SQE_INVALID_PD = 0x33,
	ERDMA_WC_VENDOR_SQE_WARP_ERR = 0x34
};

/* Response Definitions for Query Command Category */
#define ERDMA_HW_RESP_SIZE 256

struct erdma_cmdq_query_req {
	u64 hdr;
	u32 rsvd;
	u32 index;

	u64 target_addr;
	u32 target_length;
};

struct erdma_cmdq_query_resp_hdr {
	u16 magic;
	u8 ver;
	u8 length;

	u32 index;
	u32 rsvd[2];
};

struct erdma_cmdq_query_stats_resp {
	struct erdma_cmdq_query_resp_hdr hdr;

	u64 tx_req_cnt;
	u64 tx_packets_cnt;
	u64 tx_bytes_cnt;
	u64 tx_drop_packets_cnt;
	u64 tx_bps_meter_drop_packets_cnt;
	u64 tx_pps_meter_drop_packets_cnt;
	u64 rx_packets_cnt;
	u64 rx_bytes_cnt;
	u64 rx_drop_packets_cnt;
	u64 rx_bps_meter_drop_packets_cnt;
	u64 rx_pps_meter_drop_packets_cnt;
};

struct erdma_cmdq_query_qpc_resp {
	struct erdma_cmdq_query_resp_hdr hdr;

	struct{
		u8 status; /* 0 - disabled, 1 - enabled. */
		u8 qbuf_page_offset;
		u8 qbuf_page_size;
		u8 qbuf_depth;

		u16 hw_pi;
		u16 hw_ci;
	} qpc[2];

	/* hardware io stat */
	u16 last_comp_sqe_idx;
	u16 last_comp_rqe_idx;
	u16 scqe_counter;
	u16 rcqe_counter;

	u16 tx_pkts_cnt;
	u16 rx_pkts_cnt;
	u16 rx_error_drop_cnt;
	u16 rx_invalid_drop_cnt;

	u32 rto_retrans_cnt;
	//qp sw info
	u32 rqpn;

	u32 pd;
	u16 fw_sq_pi;
	u16 fw_sq_ci;

	u16 fw_rq_ci;
	u8  sq_in_flush;
	u8  rq_in_flush;
	u16 sq_flushed_pi;
	u16 rq_flushed_pi;

	u32 scqn;
	u32 rcqn;

	u64 sqbuf_addr;
	u64 rqbuf_addr;
	u64 sdbrec_addr;
	u64 rdbrec_addr;

	u64 sdbrec_cur;
	u64 rdbrec_cur;

	u32 ip_src;
	u32 ip_dst;
	u16 srcport;
	u16 dstport;
};

struct erdma_cmdq_query_cqc_resp {
	struct erdma_cmdq_query_resp_hdr hdr;

	u32 pi;
	u8 q_en;
	u8 log_depth;
	u8 cq_cur_ownership;
	u8 last_errdb_type; /* 0,dup db;1,out-order db  */

	u32 last_errdb_ci;
	u8 out_order_db_cnt;
	u8 dup_db_cnt;
	u16 rsvd;

	u64 cn_cq_db_addr;
	u64 cq_db_record;
};

struct erdma_cmdq_query_eqc_resp {
	struct erdma_cmdq_query_resp_hdr hdr;
	u16 depth;
	u16 vector;

	u8 int_suppression;
	u8 tail_owner;
	u8 head_owner;
	u8 overflow;

	u32 head;
	u32 tail;

	u64 cn_addr;
	u64 cn_db_addr;
	u64 eq_db_record;
};

struct erdma_cmdq_query_ext_attr_resp {
	struct erdma_cmdq_query_resp_hdr hdr;

	u32 cap_mask;
	u32 attr_mask;

	u8 dack_count;
};

struct erdma_cmdq_dump_addr_req {
	u64 hdr;
	u64 dump_addr;
	u64 target_addr;
	u32 target_length;
};

#endif
