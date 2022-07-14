/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */

/* Authors: Cheng Xu <chengyou@linux.alibaba.com> */
/*          Kai Shen <kaishen@linux.alibaba.com> */
/* Copyright (c) 2020-2022, Alibaba Group. */

#ifndef __ERDMA_DEBUG_H__
#define __ERDMA_DEBUG_H__

#include <linux/uaccess.h>
#include <linux/hardirq.h> /* in_interrupt() */

/*
 * dprint: Selective debug printing
 *
 * Use an OR combination of DBG_* as dbgcat in dprint*(dbgcat,...)
 * to assign debug messages to categories:
 *
 * dbgcat	Debug message belongs to category
 * ----------------------------------------------------------------------------
 * DBG_ON	Always on, for really important events or error conditions
 * DBG_TMP	Temporarily on for fine-grained debugging
 * DBG_CMDQ	used for CommandQ debugging
 * DBG_MM	Memory management
 * DBG_EH	Event handling (completion events and asynchronous events)
 * DBG_CM	Connection management, QP states
 * DBG_SK	Socket operations
 * DBG_QP	Queue pairs
 * DBG_IRQ	Interrupt context (SoftIRQ or HardIRQ)
 * DBG_DM	Device management
 * DBG_HDR	Packet HDRs
 * DBG_ALL	All categories above
 */
#define DBG_ON     0x00000001
#define DBG_TMP    0x00000002
#define DBG_CMDQ   0x00000004
#define DBG_MM     0x00000008
#define DBG_EH     0x00000010
#define DBG_CM     0x00000020
#define DBG_SK     0x00000200
#define DBG_QP     0x00000400
#define DBG_IRQ    0x00000800
#define DBG_DM     0x00001000
#define DBG_CQ     0x00004000
#define DBG_INIT   0x00008000
#define DBG_ALL                                                                \
	(DBG_IRQ | DBG_QP | DBG_SK | DBG_CM |       \
	 DBG_EH | DBG_MM | DBG_TMP | DBG_DM | DBG_ON | DBG_CMDQ |    \
	 DBG_CQ | DBG_INIT)
#define DBG_CTRL (DBG_ON | DBG_CM | DBG_DM | DBG_INIT)

/*
 * Set DPRINT_MASK to tailor your debugging needs:
 *
 * DPRINT_MASK value		Enables debug messages for
 * ---------------------------------------------------------------------
 * DBG_ON			Important events / error conditions only
 *				(minimum number of debug messages)
 * OR-ed combination of DBG_*	Selective debugging
 * DBG_QP|DBG_ON		Kernel threads
 * DBG_ALL			All categories
 */

extern __u32 dprint_mask;

/**
 * dprint - Selective debug print for process, SoftIRQ or HardIRQ context
 *
 * Debug print with selectable debug categories,
 * starting with header
 * - "( pid /cpu) __func__" for process context
 * - "( irq /cpu) __func__" for IRQ context
 *
 * @dbgcat	: Set of debug categories (OR-ed combination of DBG_* above),
 *		  to which this debug message is assigned.
 * @fmt		: printf compliant format string
 * @args	: printf compliant argument list
 */

#define dprint(dbgcat, fmt, args...)                                           \
	do {                                                                   \
		if ((dbgcat)&dprint_mask) {                                    \
			if (!in_interrupt())                                   \
				pr_info("(%5d/%1d) %s:" fmt, current->pid,     \
					task_cpu(current), __func__, ##args);       \
			else                                                   \
				pr_info("( irq /%1d) %s:" fmt, task_cpu(current),   \
					__func__, ##args);                     \
		}                                                              \
	} while (0)


#endif
