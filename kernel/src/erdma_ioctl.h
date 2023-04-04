/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */

/* Authors: Cheng Xu <chengyou@linux.alibaba.com> */
/* Copyright (c) 2020-2022, Alibaba Group. */

#ifndef __EADM_IOCTL_H__
#define __EADM_IOCTL_H__

#include <linux/ioctl.h>
#include <linux/kernel.h>
#ifdef __KERNEL__
#include <linux/sched.h>
#else
#define TASK_COMM_LEN 16
#endif

#define ERDMA_DEVICE_NAME_MAX_LEN 20

enum erdma_cmd {
	EADM_DUMP_CMD = 0x0,
	EADM_TEST_CMD,
	EADM_CTRL_CMD,
	EADM_STAT_CMD,
	EADM_INFO_CMD,
	EADM_CONF_CMD,
	EADM_VER_CMD,
	EADM_CMD_MAX,
};

#define ERDMA_DUMP_OPCODE_CQE 0
#define ERDMA_DUMP_OPCODE_SQE 1
#define ERDMA_DUMP_OPCODE_RQE 2
#define ERDMA_DUMP_OPCODE_EQE 3

#define ERDMA_CM_TEST_SERVER       0
#define ERDMA_CM_TEST_CLIENT   1

#define ERDMA_TEST_DATA       3
#define ERDMA_TEST_ECHO       4
#define ERDMA_TEST_CONN       5
#define ERDMA_TEST_ORDER      6

enum erdma_stat_type {
	ERDMA_STAT_TYPE_QP = 0,
	ERDMA_STAT_TYPE_CQ,
	ERDMA_STAT_TYPE_DEV,
	ERDMA_STAT_TYPE_MAX,
};

enum erdma_info_type {
	ERDMA_INFO_TYPE_DEV = 0,
	ERDMA_INFO_TYPE_ALLOCED_QP,
	ERDMA_INFO_TYPE_QP,
	ERDMA_INFO_TYPE_ALLOCED_CQ,
	ERDMA_INFO_TYPE_CQ,
	ERDMA_INFO_TYPE_EQ,
	ERDMA_INFO_TYPE_CEP,
	ERDMA_INFO_TYPE_MAX,
};

enum erdma_config_type {
	ERDMA_CONFIG_TYPE_CC = 0,
	ERDMA_CONFIG_TYPE_LOGLEVEL,
	ERDMA_CONFIG_TYPE_RETRANS_NUM,
	ERDMA_CONFIG_MAX
};

enum erdma_dump_type {
	ERDMA_DUMP_TYPE_SQE = 0,
	ERDMA_DUMP_TYPE_RQE,
	ERDMA_DUMP_TYPE_CQE,
	ERDMA_DUMP_TYPE_EQE,
	ERDMA_DUMP_MAX = ERDMA_DUMP_TYPE_EQE + 1,
};

struct erdma_qp_info {
	__u32 qpn;
	__u32 qp_state;
	__u32 ref_cnt;

	__u32 sip;
	__u32 dip;
	__u16 sport;
	__u16 dport;

	__u16 qtype; /* Client or Server. */
	__u16 origin_sport;
	__u16 sq_depth;
	__u16 rq_depth;

	__u32 cookie;
	__u8 cc;
	__u8 is_user;
	__u8 sq_mtt_type;
	__u8 rq_mtt_type;

	__u32 assoc_scqn;
	__u32 assoc_rcqn;

	__u16 sqci;
	__u16 sqpi;
	__u16 rqci;
	__u16 rqpi;
	__u64 sqbuf_dma;
	__u64 rqbuf_dma;
	__u64 sqdbrec_dma;
	__u64 rqdbrec_dma;

	__u32 pid;
	char buf[TASK_COMM_LEN];
	__u8 rsvd0[15];
	__u8 hw_info_valid;

	struct {
		__u32 page_size;
		__u32 page_offset;
		__u32 page_cnt;
		__u32 mtt_nents;
		__u64 mtt_entry[4];
		__u64 va;
		__u64 len;
	} sq_mtt, rq_mtt;

	__u8 sq_enable;
	__u8 sqbuf_page_offset;
	__u8 sqbuf_page_size;
	__u8 sqbuf_depth;
	__u16 hw_sq_ci;
	__u16 hw_sq_pi;

	__u8 rq_enable;
	__u8 rqbuf_page_offset;
	__u8 rqbuf_page_size;
	__u8 rqbuf_depth;
	__u16 hw_rq_ci;
	__u16 hw_rq_pi;

	__u16 last_comp_sqe_idx;
	__u16 last_comp_rqe_idx;
	__u16 scqe_counter;
	__u16 rcqe_counter;
	__u16 tx_pkts_cnt;
	__u16 rx_pkts_cnt;
	__u16 rx_error_drop_cnt;
	__u16 rx_invalid_drop_cnt;
	__u32 rto_retrans_cnt;

	__u32 pd;
	__u16 fw_sq_pi;
	__u16 fw_sq_ci;
	__u16 fw_rq_ci;
	__u8  sq_in_flush;
	__u8  rq_in_flush;

	__u16 sq_flushed_pi;
	__u16 rq_flushed_pi;

	__u64 sqbuf_addr;
	__u64 rqbuf_addr;
	__u64 sdbrec_addr;
	__u64 rdbrec_addr;
	__u64 sdbrec_val;
	__u64 rdbrec_val;

	__u32 ip_src;
	__u32 ip_dst;
	__u16 srcport;
	__u16 dstport;
};

struct erdma_cq_info {
	__u32 cqn;
	__u32 depth;

	__u32 assoc_eqn;
	__u8 is_user;
	__u8 rsvd0;
	__u8 mtt_type;
	__u8 hw_info_valid;

	__u64 qbuf_dma_addr;
	__u32 ci;
	__u32 cmdsn;
	__u32 notify_cnt;
	__u32 rsvd1;

	struct {
		__u32 page_size;
		__u32 page_offset;
		__u32 page_cnt;
		__u32 mtt_nents;
		__u64 mtt_entry[4];
		__u64 va;
		__u64 len;
	} mtt;

	__u32 hw_pi;
	__u8 enable;
	__u8 log_depth;
	__u8 cq_cur_ownership;
	__u8 last_errdb_type; /* 0,dup db;1,out-order db  */

	__u32 last_errdb_ci;
	__u8 out_order_db_cnt;
	__u8 dup_db_cnt;
	__u16 rsvd;

	__u64 cn_cq_db_addr;
	__u64 cq_db_record;
};

struct erdma_eq_info {
	__u32 eqn;
	__u8 ready;
	__u8 rsvd[2];
	__u8 hw_info_valid;

	__u64 event_cnt;
	__u64 notify_cnt;

	__u32 depth;
	__u32 ci;
	__u64 qbuf_dma;
	__u64 qbuf_va;

	__u16 hw_depth;
	__u16 vector;

	__u8 int_suppression;
	__u8 tail_owner;
	__u8 head_owner;
	__u8 overflow;

	__u32 head;
	__u32 tail;

	__u64 cn_addr;
	__u64 cn_db_addr;
	__u64 eq_db_record;

};

struct erdma_ioctl_inbuf {
	__u32 opcode;
	char ibdev_name[ERDMA_DEVICE_NAME_MAX_LEN + 1];
	union {
		struct {
			__u32 value;
			__u32 is_set;
		} config_req;

		struct {
			__u32 qn;
			__u32 qe_idx;
		} dump_req;
		struct {
			__u32 qn;
			__u32 max_result_cnt;
		} info_req;
		struct {
			__u32 qn;
		} stat_req;
	};
};

struct erdma_ioctl_outbuf {
	__u32 status;
	__u32 length;
	union {
		char data[4096];
		struct {
			__u32 value;
		} config_resp;

		__u32 allocted_qpn[1024];
		__u32 allocted_cqn[1024];

		struct erdma_qp_info qp_info;
		/* 0: AEQ, 1: Cmd-EQ, 2-32: Completion-EQ */
		struct erdma_eq_info eq_info[33];
		struct erdma_cq_info cq_info;

		__u32 version;
		__u64 stats[512];
	};
};

struct erdma_ioctl_msg {
	struct erdma_ioctl_inbuf in;
	struct erdma_ioctl_outbuf out;
};

/* 定义幻数 */
#define ERDMA_IOC_MAGIC  'k'

/* 定义命令 */
#define ERDMA_DUMP _IOWR(ERDMA_IOC_MAGIC, EADM_DUMP_CMD, struct erdma_ioctl_msg)
#define ERDMA_TEST _IOWR(ERDMA_IOC_MAGIC, EADM_TEST_CMD, struct erdma_ioctl_msg)
#define ERDMA_CTRL _IOWR(ERDMA_IOC_MAGIC, EADM_CTRL_CMD, struct erdma_ioctl_msg)
#define ERDMA_STAT _IOWR(ERDMA_IOC_MAGIC, EADM_STAT_CMD, struct erdma_ioctl_msg)
#define ERDMA_INFO _IOWR(ERDMA_IOC_MAGIC, EADM_INFO_CMD, struct erdma_ioctl_msg)
#define ERDMA_CONF _IOWR(ERDMA_IOC_MAGIC, EADM_CONF_CMD, struct erdma_ioctl_msg)
#define ERDMA_VER _IOWR(ERDMA_IOC_MAGIC, EADM_VER_CMD, struct erdma_ioctl_msg)

#define ERDMA_IOC_MAXNR EADM_CMD_MAX

#ifdef __KERNEL__
long chardev_ioctl(struct file *filp, unsigned int cmd, unsigned long arg);
long do_ioctl(unsigned int cmd, unsigned long arg);
#else

#endif
int exec_ioctl_cmd(char *dev_path, int cmd, struct erdma_ioctl_msg *msg);

#endif
