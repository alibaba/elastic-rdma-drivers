/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
 * Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.
 */

#ifndef SW_QUEUE_H
#define SW_QUEUE_H

/* implements a simple circular buffer that can optionally be
 * shared between user space and the kernel and can be resized

 * the requested element size is rounded up to a power of 2
 * and the number of elements in the buffer is also rounded
 * up to a power of 2. Since the queue is empty when the
 * producer and consumer indices match the maximum capacity
 * of the queue is one less than the number of element slots
 */

/* this data structure is shared between user space and kernel
 * space for those cases where the queue is shared. It contains
 * the producer and consumer indices. Is also contains a copy
 * of the queue size parameters for user space to use but the
 * kernel must use the parameters in the sw_queue struct
 * this MUST MATCH the corresponding libsw struct
 * for performance reasons arrange to have producer and consumer
 * pointers in separate cache lines
 * the kernel should always mask the indices to avoid accessing
 * memory outside of the data area
 */
struct sw_queue_buf {
	__u32			log2_elem_size;
	__u32			index_mask;
	__u32			pad_1[30];
	__u32			producer_index;
	__u32			pad_2[31];
	__u32			consumer_index;
	__u32			pad_3[31];
	__u8			data[];
};

struct sw_queue {
	struct sw_dev		*sw;
	struct sw_queue_buf	*buf;
	struct sw_mmap_info	*ip;
	size_t			buf_size;
	size_t			elem_size;
	unsigned int		log2_elem_size;
	unsigned int		index_mask;
};

void sw_queue_reset(struct sw_queue *q);

struct sw_queue *sw_queue_init(struct sw_dev *sw,
				 int *num_elem,
				 unsigned int elem_size);

void sw_queue_cleanup(struct sw_queue *queue);

static inline int next_index(struct sw_queue *q, int index)
{
	return (index + 1) & q->buf->index_mask;
}

static inline int queue_empty(struct sw_queue *q)
{
	return ((q->buf->producer_index - q->buf->consumer_index)
			& q->index_mask) == 0;
}

static inline int queue_full(struct sw_queue *q)
{
	return ((q->buf->producer_index + 1 - q->buf->consumer_index)
			& q->index_mask) == 0;
}

static inline void advance_producer(struct sw_queue *q)
{
	q->buf->producer_index = (q->buf->producer_index + 1)
			& q->index_mask;
}

static inline void advance_consumer(struct sw_queue *q)
{
	q->buf->consumer_index = (q->buf->consumer_index + 1)
			& q->index_mask;
}

static inline void *producer_addr(struct sw_queue *q)
{
	return q->buf->data + ((q->buf->producer_index & q->index_mask)
				<< q->log2_elem_size);
}

static inline void *consumer_addr(struct sw_queue *q)
{
	return q->buf->data + ((q->buf->consumer_index & q->index_mask)
				<< q->log2_elem_size);
}

static inline unsigned int producer_index(struct sw_queue *q)
{
	return q->buf->producer_index;
}

static inline unsigned int consumer_index(struct sw_queue *q)
{
	return q->buf->consumer_index;
}

static inline void *addr_from_index(struct sw_queue *q, unsigned int index)
{
	return q->buf->data + ((index & q->index_mask)
				<< q->buf->log2_elem_size);
}

static inline unsigned int index_from_addr(const struct sw_queue *q,
					   const void *addr)
{
	return (((u8 *)addr - q->buf->data) >> q->log2_elem_size)
		& q->index_mask;
}

static inline unsigned int queue_count(const struct sw_queue *q)
{
	return (q->buf->producer_index - q->buf->consumer_index)
		& q->index_mask;
}

static inline void *queue_head(struct sw_queue *q)
{
	return queue_empty(q) ? NULL : consumer_addr(q);
}

#endif /* SW_QUEUE_H */
