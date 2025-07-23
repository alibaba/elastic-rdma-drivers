/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
 * Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.
 */

#ifndef SW_POOL_H
#define SW_POOL_H

#define SW_POOL_ALIGN		(16)
#define SW_POOL_CACHE_FLAGS	(0)

enum sw_pool_flags {
	SW_POOL_ATOMIC		= BIT(0),
	SW_POOL_INDEX		= BIT(1),
	SW_POOL_KEY		= BIT(2),
	SW_POOL_NO_ALLOC	= BIT(4),
};

enum sw_elem_type {
	SW_TYPE_UC,
	SW_TYPE_PD,
	SW_TYPE_AH,
	SW_TYPE_SRQ,
	SW_TYPE_QP,
	SW_TYPE_CQ,
	SW_TYPE_MR,
	SW_TYPE_MW,
	SW_TYPE_MC_GRP,
	SW_TYPE_MC_ELEM,
	SW_NUM_TYPES,		/* keep me last */
};

struct sw_pool_entry;

struct sw_type_info {
	const char		*name;
	size_t			size;
	void			(*cleanup)(struct sw_pool_entry *obj);
	enum sw_pool_flags	flags;
	u32			max_index;
	u32			min_index;
	size_t			key_offset;
	size_t			key_size;
};

extern struct sw_type_info sw_type_info[];

enum sw_pool_state {
	SW_POOL_STATE_INVALID,
	SW_POOL_STATE_VALID,
};

struct sw_pool_entry {
	struct sw_pool		*pool;
	struct kref		ref_cnt;
	struct list_head	list;

	/* only used if indexed or keyed */
	struct rb_node		node;
	u32			index;
};

struct sw_pool {
	struct sw_dev		*sw;
	rwlock_t		pool_lock; /* protects pool add/del/search */
	size_t			elem_size;
	struct kref		ref_cnt;
	void			(*cleanup)(struct sw_pool_entry *obj);
	enum sw_pool_state	state;
	enum sw_pool_flags	flags;
	enum sw_elem_type	type;

	unsigned int		max_elem;
	atomic_t		num_elem;

	/* only used if indexed or keyed */
	struct rb_root		tree;
	unsigned long		*table;
	size_t			table_size;
	u32			max_index;
	u32			min_index;
	u32			last;
	size_t			key_offset;
	size_t			key_size;
};

/* initialize a pool of objects with given limit on
 * number of elements. gets parameters from sw_type_info
 * pool elements will be allocated out of a slab cache
 */
int sw_pool_init(struct sw_dev *sw, struct sw_pool *pool,
		  enum sw_elem_type type, u32 max_elem);

/* free resources from object pool */
void sw_pool_cleanup(struct sw_pool *pool);

/* allocate an object from pool */
void *sw_alloc(struct sw_pool *pool);

/* connect already allocated object to pool */
int sw_add_to_pool(struct sw_pool *pool, struct sw_pool_entry *elem);

/* assign an index to an indexed object and insert object into
 *  pool's rb tree
 */
void sw_add_index(void *elem);

/* drop an index and remove object from rb tree */
void sw_drop_index(void *elem);

/* assign a key to a keyed object and insert object into
 *  pool's rb tree
 */
void sw_add_key(void *elem, void *key);

/* remove elem from rb tree */
void sw_drop_key(void *elem);

/* lookup an indexed object from index. takes a reference on object */
void *sw_pool_get_index(struct sw_pool *pool, u32 index);

/* lookup keyed object from key. takes a reference on the object */
void *sw_pool_get_key(struct sw_pool *pool, void *key);

/* cleanup an object when all references are dropped */
void sw_elem_release(struct kref *kref);

/* take a reference on an object */
#define sw_add_ref(elem) kref_get(&(elem)->pelem.ref_cnt)

/* drop a reference on an object */
#define sw_drop_ref(elem) kref_put(&(elem)->pelem.ref_cnt, sw_elem_release)

#endif /* SW_POOL_H */
