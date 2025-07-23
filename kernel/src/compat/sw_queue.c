// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
 * Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.
 */

#include <linux/vmalloc.h>
#include "sw.h"
#include "sw_loc.h"
#include "sw_queue.h"

inline void sw_queue_reset(struct sw_queue *q)
{
	/* queue is comprised from header and the memory
	 * of the actual queue. See "struct sw_queue_buf" in sw_queue.h
	 * reset only the queue itself and not the management header
	 */
	memset(q->buf->data, 0, q->buf_size - sizeof(struct sw_queue_buf));
}

struct sw_queue *sw_queue_init(struct sw_dev *sw,
				 int *num_elem,
				 unsigned int elem_size)
{
	struct sw_queue *q;
	size_t buf_size;
	unsigned int num_slots;

	/* num_elem == 0 is allowed, but uninteresting */
	if (*num_elem < 0)
		goto err1;

	q = kmalloc(sizeof(*q), GFP_KERNEL);
	if (!q)
		goto err1;

	q->sw = sw;

	/* used in resize, only need to copy used part of queue */
	q->elem_size = elem_size;

	/* pad element up to at least a cacheline and always a power of 2 */
	if (elem_size < cache_line_size())
		elem_size = cache_line_size();
	elem_size = roundup_pow_of_two(elem_size);

	q->log2_elem_size = order_base_2(elem_size);

	num_slots = *num_elem + 1;
	num_slots = roundup_pow_of_two(num_slots);
	q->index_mask = num_slots - 1;

	buf_size = sizeof(struct sw_queue_buf) + num_slots * elem_size;

	q->buf = vmalloc_user(buf_size);
	if (!q->buf)
		goto err2;

	q->buf->log2_elem_size = q->log2_elem_size;
	q->buf->index_mask = q->index_mask;

	q->buf_size = buf_size;

	*num_elem = num_slots - 1;
	return q;

err2:
	kfree(q);
err1:
	return NULL;
}

void sw_queue_cleanup(struct sw_queue *q)
{
	vfree(q->buf);
	kfree(q);
}
