/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
 * Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.
 */

#ifndef SW_OPCODE_H
#define SW_OPCODE_H

/*
 * contains header bit mask definitions and header lengths
 * declaration of the sw_opcode_info struct and
 * sw_wr_opcode_info struct
 */

enum sw_wr_mask {
	WR_INLINE_MASK			= BIT(0),
	WR_ATOMIC_MASK			= BIT(1),
	WR_SEND_MASK			= BIT(2),
	WR_READ_MASK			= BIT(3),
	WR_WRITE_MASK			= BIT(4),
	WR_LOCAL_MASK			= BIT(5),
	WR_REG_MASK			= BIT(6),

	WR_READ_OR_WRITE_MASK		= WR_READ_MASK | WR_WRITE_MASK,
	WR_READ_WRITE_OR_SEND_MASK	= WR_READ_OR_WRITE_MASK | WR_SEND_MASK,
	WR_WRITE_OR_SEND_MASK		= WR_WRITE_MASK | WR_SEND_MASK,
	WR_ATOMIC_OR_READ_MASK		= WR_ATOMIC_MASK | WR_READ_MASK,
};

#define WR_MAX_QPT		(8)

struct sw_wr_opcode_info {
	char			*name;
	enum sw_wr_mask	mask[WR_MAX_QPT];
};

extern struct sw_wr_opcode_info sw_wr_opcode_info[];

enum sw_hdr_type {
	SW_LRH,
	SW_GRH,
	SW_BTH,
	SW_RETH,
	SW_AETH,
	SW_ATMETH,
	SW_ATMACK,
	SW_IETH,
	SW_RDETH,
	SW_DETH,
	SW_IMMDT,
	SW_PAYLOAD,
	NUM_HDR_TYPES
};

enum sw_hdr_mask {
	SW_LRH_MASK		= BIT(SW_LRH),
	SW_GRH_MASK		= BIT(SW_GRH),
	SW_BTH_MASK		= BIT(SW_BTH),
	SW_IMMDT_MASK		= BIT(SW_IMMDT),
	SW_RETH_MASK		= BIT(SW_RETH),
	SW_AETH_MASK		= BIT(SW_AETH),
	SW_ATMETH_MASK		= BIT(SW_ATMETH),
	SW_ATMACK_MASK		= BIT(SW_ATMACK),
	SW_IETH_MASK		= BIT(SW_IETH),
	SW_RDETH_MASK		= BIT(SW_RDETH),
	SW_DETH_MASK		= BIT(SW_DETH),
	SW_PAYLOAD_MASK	= BIT(SW_PAYLOAD),

	SW_REQ_MASK		= BIT(NUM_HDR_TYPES + 0),
	SW_ACK_MASK		= BIT(NUM_HDR_TYPES + 1),
	SW_SEND_MASK		= BIT(NUM_HDR_TYPES + 2),
	SW_WRITE_MASK		= BIT(NUM_HDR_TYPES + 3),
	SW_READ_MASK		= BIT(NUM_HDR_TYPES + 4),
	SW_ATOMIC_MASK		= BIT(NUM_HDR_TYPES + 5),

	SW_RWR_MASK		= BIT(NUM_HDR_TYPES + 6),
	SW_COMP_MASK		= BIT(NUM_HDR_TYPES + 7),

	SW_START_MASK		= BIT(NUM_HDR_TYPES + 8),
	SW_MIDDLE_MASK		= BIT(NUM_HDR_TYPES + 9),
	SW_END_MASK		= BIT(NUM_HDR_TYPES + 10),

	SW_LOOPBACK_MASK	= BIT(NUM_HDR_TYPES + 12),

	SW_READ_OR_ATOMIC	= (SW_READ_MASK | SW_ATOMIC_MASK),
	SW_WRITE_OR_SEND	= (SW_WRITE_MASK | SW_SEND_MASK),
};

#define OPCODE_NONE		(-1)
#define SW_NUM_OPCODE		256

struct sw_opcode_info {
	char			*name;
	enum sw_hdr_mask	mask;
	int			length;
	int			offset[NUM_HDR_TYPES];
};

extern struct sw_opcode_info sw_opcode[SW_NUM_OPCODE];

#endif /* SW_OPCODE_H */
