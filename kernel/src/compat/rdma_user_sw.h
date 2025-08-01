/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR Linux-OpenIB) */
/*
 * Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *	- Redistributions of source code must retain the above
 *	  copyright notice, this list of conditions and the following
 *	  disclaimer.
 *
 *	- Redistributions in binary form must reproduce the above
 *	  copyright notice, this list of conditions and the following
 *	  disclaimer in the documentation and/or other materials
 *	  provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef RDMA_USER_SW_H
#define RDMA_USER_SW_H

#include <linux/types.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/in6.h>

enum {
	SW_NETWORK_TYPE_IPV4 = 1,
	SW_NETWORK_TYPE_IPV6 = 2,
};

union sw_gid {
	__u8	raw[16];
	struct {
		__be64	subnet_prefix;
		__be64	interface_id;
	} global;
};

struct sw_global_route {
	union sw_gid	dgid;
	__u32		flow_label;
	__u8		sgid_index;
	__u8		hop_limit;
	__u8		traffic_class;
};

struct sw_av {
	__u8			port_num;
	/* From SW_NETWORK_TYPE_* */
	__u8			network_type;
	__u8			dmac[6];
	struct sw_global_route	grh;
	union {
		struct sockaddr_in	_sockaddr_in;
		struct sockaddr_in6	_sockaddr_in6;
	} sgid_addr, dgid_addr;
};

struct sw_send_wr {
	__aligned_u64		wr_id;
	__u32			num_sge;
	__u32			opcode;
	__u32			send_flags;
	union {
		__be32		imm_data;
		__u32		invalidate_rkey;
	} ex;
	union {
		struct {
			__aligned_u64 remote_addr;
			__u32	rkey;
			__u32	reserved;
		} rdma;
		struct {
			__aligned_u64 remote_addr;
			__aligned_u64 compare_add;
			__aligned_u64 swap;
			__u32	rkey;
			__u32	reserved;
		} atomic;
		struct {
			__u32	remote_qpn;
			__u32	remote_qkey;
			__u16	pkey_index;
		} ud;
		/* reg is only used by the kernel and is not part of the uapi */
		struct {
			union {
				struct ib_mr *mr;
				__aligned_u64 reserved;
			};
			__u32	     key;
			__u32	     access;
		} reg;
	} wr;
};

struct sw_sge {
	__aligned_u64 addr;
	__u32	length;
	__u32	lkey;
};

struct mminfo {
	__aligned_u64		offset;
	__u32			size;
	__u32			pad;
};

struct sw_dma_info {
	__u32			length;
	__u32			resid;
	__u32			cur_sge;
	__u32			num_sge;
	__u32			sge_offset;
	__u32			reserved;
	union {
		__u8		inline_data[0];
		struct sw_sge	sge[0];
	};
};

struct sw_send_wqe {
	struct sw_send_wr	wr;
	struct sw_av		av;
	__u32			status;
	__u32			state;
	__aligned_u64		iova;
	__u32			mask;
	__u32			first_psn;
	__u32			last_psn;
	__u32			ack_length;
	__u32			ssn;
	__u32			has_rd_atomic;
	struct sw_dma_info	dma;
};

struct sw_recv_wqe {
	__aligned_u64		wr_id;
	__u32			num_sge;
	__u32			padding;
	struct sw_dma_info	dma;
};

struct sw_create_cq_resp {
	struct mminfo mi;
};

struct sw_resize_cq_resp {
	struct mminfo mi;
};

struct sw_create_qp_resp {
	struct mminfo rq_mi;
	struct mminfo sq_mi;
};

struct sw_create_srq_resp {
	struct mminfo mi;
	__u32 srq_num;
	__u32 reserved;
};

struct sw_modify_srq_cmd {
	__aligned_u64 mmap_info_addr;
};

#endif /* RDMA_USER_SW_H */
