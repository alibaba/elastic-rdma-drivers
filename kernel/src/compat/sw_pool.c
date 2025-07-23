// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
 * Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.
 */

#include "sw.h"
#include "sw_loc.h"

/* info about object pools
 * note that mr and mw share a single index space
 * so that one can map an lkey to the correct type of object
 */
struct sw_type_info sw_type_info[SW_NUM_TYPES] = {
	[SW_TYPE_UC] = {
		.name		= "sw-uc",
		.size		= sizeof(struct sw_ucontext),
		.flags          = SW_POOL_NO_ALLOC,
	},
	[SW_TYPE_PD] = {
		.name		= "sw-pd",
		.size		= sizeof(struct sw_pd),
		.flags		= SW_POOL_NO_ALLOC,
	},
	[SW_TYPE_AH] = {
		.name		= "sw-ah",
		.size		= sizeof(struct sw_ah),
		.flags		= SW_POOL_ATOMIC | SW_POOL_NO_ALLOC,
	},
	[SW_TYPE_SRQ] = {
		.name		= "sw-srq",
		.size		= sizeof(struct sw_srq),
		.flags		= SW_POOL_INDEX | SW_POOL_NO_ALLOC,
		.min_index	= SW_MIN_SRQ_INDEX,
		.max_index	= SW_MAX_SRQ_INDEX,
	},
	[SW_TYPE_QP] = {
		.name		= "sw-qp",
		.size		= sizeof(struct sw_qp),
		.cleanup	= sw_qp_cleanup,
		.flags		= SW_POOL_INDEX,
		.min_index	= SW_MIN_QP_INDEX,
		.max_index	= SW_MAX_QP_INDEX,
	},
	[SW_TYPE_CQ] = {
		.name		= "sw-cq",
		.size		= sizeof(struct sw_cq),
		.flags          = SW_POOL_NO_ALLOC,
		.cleanup	= sw_cq_cleanup,
	},
	[SW_TYPE_MR] = {
		.name		= "sw-mr",
		.size		= sizeof(struct sw_mem),
		.cleanup	= sw_mem_cleanup,
		.flags		= SW_POOL_INDEX,
		.max_index	= SW_MAX_MR_INDEX,
		.min_index	= SW_MIN_MR_INDEX,
	},
	[SW_TYPE_MW] = {
		.name		= "sw-mw",
		.size		= sizeof(struct sw_mem),
		.flags		= SW_POOL_INDEX,
		.max_index	= SW_MAX_MW_INDEX,
		.min_index	= SW_MIN_MW_INDEX,
	},
	[SW_TYPE_MC_GRP] = {
		.name		= "sw-mc_grp",
		.size		= sizeof(struct sw_mc_grp),
		.cleanup	= sw_mc_cleanup,
		.flags		= SW_POOL_KEY,
		.key_offset	= offsetof(struct sw_mc_grp, mgid),
		.key_size	= sizeof(union ib_gid),
	},
	[SW_TYPE_MC_ELEM] = {
		.name		= "sw-mc_elem",
		.size		= sizeof(struct sw_mc_elem),
		.flags		= SW_POOL_ATOMIC,
	},
};

static inline const char *pool_name(struct sw_pool *pool)
{
	return sw_type_info[pool->type].name;
}

static int sw_pool_init_index(struct sw_pool *pool, u32 max, u32 min)
{
	int err = 0;
	size_t size;

	if ((max - min + 1) < pool->max_elem) {
		pr_warn("not enough indices for max_elem\n");
		err = -EINVAL;
		goto out;
	}

	pool->max_index = max;
	pool->min_index = min;

	size = BITS_TO_LONGS(max - min + 1) * sizeof(long);
	pool->table = kmalloc(size, GFP_KERNEL);
	if (!pool->table) {
		err = -ENOMEM;
		goto out;
	}

	pool->table_size = size;
	bitmap_zero(pool->table, max - min + 1);

out:
	return err;
}

int sw_pool_init(
	struct sw_dev		*sw,
	struct sw_pool		*pool,
	enum sw_elem_type	type,
	unsigned int		max_elem)
{
	int			err = 0;
	size_t			size = sw_type_info[type].size;

	memset(pool, 0, sizeof(*pool));

	pool->sw		= sw;
	pool->type		= type;
	pool->max_elem		= max_elem;
	pool->elem_size		= ALIGN(size, SW_POOL_ALIGN);
	pool->flags		= sw_type_info[type].flags;
	pool->tree		= RB_ROOT;
	pool->cleanup		= sw_type_info[type].cleanup;

	atomic_set(&pool->num_elem, 0);

	kref_init(&pool->ref_cnt);

	rwlock_init(&pool->pool_lock);

	if (sw_type_info[type].flags & SW_POOL_INDEX) {
		err = sw_pool_init_index(pool,
					  sw_type_info[type].max_index,
					  sw_type_info[type].min_index);
		if (err)
			goto out;
	}

	if (sw_type_info[type].flags & SW_POOL_KEY) {
		pool->key_offset = sw_type_info[type].key_offset;
		pool->key_size = sw_type_info[type].key_size;
	}

	pool->state = SW_POOL_STATE_VALID;

out:
	return err;
}

static void sw_pool_release(struct kref *kref)
{
	struct sw_pool *pool = container_of(kref, struct sw_pool, ref_cnt);

	pool->state = SW_POOL_STATE_INVALID;
	kfree(pool->table);
}

static void sw_pool_put(struct sw_pool *pool)
{
	kref_put(&pool->ref_cnt, sw_pool_release);
}

void sw_pool_cleanup(struct sw_pool *pool)
{
	unsigned long flags;

	write_lock_irqsave(&pool->pool_lock, flags);
	pool->state = SW_POOL_STATE_INVALID;
	if (atomic_read(&pool->num_elem) > 0)
		pr_warn("%s pool destroyed with unfree'd elem\n",
			pool_name(pool));
	write_unlock_irqrestore(&pool->pool_lock, flags);

	sw_pool_put(pool);
}

static u32 alloc_index(struct sw_pool *pool)
{
	u32 index;
	u32 range = pool->max_index - pool->min_index + 1;

	index = find_next_zero_bit(pool->table, range, pool->last);
	if (index >= range)
		index = find_first_zero_bit(pool->table, range);

	WARN_ON_ONCE(index >= range);
	set_bit(index, pool->table);
	pool->last = index;
	return index + pool->min_index;
}

static void insert_index(struct sw_pool *pool, struct sw_pool_entry *new)
{
	struct rb_node **link = &pool->tree.rb_node;
	struct rb_node *parent = NULL;
	struct sw_pool_entry *elem;

	while (*link) {
		parent = *link;
		elem = rb_entry(parent, struct sw_pool_entry, node);

		if (elem->index == new->index) {
			pr_warn("element already exists!\n");
			goto out;
		}

		if (elem->index > new->index)
			link = &(*link)->rb_left;
		else
			link = &(*link)->rb_right;
	}

	rb_link_node(&new->node, parent, link);
	rb_insert_color(&new->node, &pool->tree);
out:
	return;
}

static void insert_key(struct sw_pool *pool, struct sw_pool_entry *new)
{
	struct rb_node **link = &pool->tree.rb_node;
	struct rb_node *parent = NULL;
	struct sw_pool_entry *elem;
	int cmp;

	while (*link) {
		parent = *link;
		elem = rb_entry(parent, struct sw_pool_entry, node);

		cmp = memcmp((u8 *)elem + pool->key_offset,
			     (u8 *)new + pool->key_offset, pool->key_size);

		if (cmp == 0) {
			pr_warn("key already exists!\n");
			goto out;
		}

		if (cmp > 0)
			link = &(*link)->rb_left;
		else
			link = &(*link)->rb_right;
	}

	rb_link_node(&new->node, parent, link);
	rb_insert_color(&new->node, &pool->tree);
out:
	return;
}

void sw_add_key(void *arg, void *key)
{
	struct sw_pool_entry *elem = arg;
	struct sw_pool *pool = elem->pool;
	unsigned long flags;

	write_lock_irqsave(&pool->pool_lock, flags);
	memcpy((u8 *)elem + pool->key_offset, key, pool->key_size);
	insert_key(pool, elem);
	write_unlock_irqrestore(&pool->pool_lock, flags);
}

void sw_drop_key(void *arg)
{
	struct sw_pool_entry *elem = arg;
	struct sw_pool *pool = elem->pool;
	unsigned long flags;

	write_lock_irqsave(&pool->pool_lock, flags);
	rb_erase(&elem->node, &pool->tree);
	write_unlock_irqrestore(&pool->pool_lock, flags);
}

void sw_add_index(void *arg)
{
	struct sw_pool_entry *elem = arg;
	struct sw_pool *pool = elem->pool;
	unsigned long flags;

	write_lock_irqsave(&pool->pool_lock, flags);
	elem->index = alloc_index(pool);
	insert_index(pool, elem);
	write_unlock_irqrestore(&pool->pool_lock, flags);
}

void sw_drop_index(void *arg)
{
	struct sw_pool_entry *elem = arg;
	struct sw_pool *pool = elem->pool;
	unsigned long flags;

	write_lock_irqsave(&pool->pool_lock, flags);
	clear_bit(elem->index - pool->min_index, pool->table);
	rb_erase(&elem->node, &pool->tree);
	write_unlock_irqrestore(&pool->pool_lock, flags);
}

void *sw_alloc(struct sw_pool *pool)
{
	struct sw_pool_entry *elem;
	unsigned long flags;

	might_sleep_if(!(pool->flags & SW_POOL_ATOMIC));

	read_lock_irqsave(&pool->pool_lock, flags);
	if (pool->state != SW_POOL_STATE_VALID) {
		read_unlock_irqrestore(&pool->pool_lock, flags);
		return NULL;
	}
	kref_get(&pool->ref_cnt);
	read_unlock_irqrestore(&pool->pool_lock, flags);

	if (atomic_inc_return(&pool->num_elem) > pool->max_elem)
		goto out_cnt;

	elem = kzalloc(sw_type_info[pool->type].size,
				 (pool->flags & SW_POOL_ATOMIC) ?
				 GFP_ATOMIC : GFP_KERNEL);
	if (!elem)
		goto out_cnt;

	elem->pool = pool;
	kref_init(&elem->ref_cnt);

	return elem;

out_cnt:
	atomic_dec(&pool->num_elem);
	sw_pool_put(pool);
	return NULL;
}

int sw_add_to_pool(struct sw_pool *pool, struct sw_pool_entry *elem)
{
	unsigned long flags;

	might_sleep_if(!(pool->flags & SW_POOL_ATOMIC));

	read_lock_irqsave(&pool->pool_lock, flags);
	if (pool->state != SW_POOL_STATE_VALID) {
		read_unlock_irqrestore(&pool->pool_lock, flags);
		return -EINVAL;
	}
	kref_get(&pool->ref_cnt);
	read_unlock_irqrestore(&pool->pool_lock, flags);

	if (atomic_inc_return(&pool->num_elem) > pool->max_elem)
		goto out_cnt;

	elem->pool = pool;
	kref_init(&elem->ref_cnt);

	return 0;

out_cnt:
	atomic_dec(&pool->num_elem);
	sw_pool_put(pool);
	return -EINVAL;
}

void sw_elem_release(struct kref *kref)
{
	struct sw_pool_entry *elem =
		container_of(kref, struct sw_pool_entry, ref_cnt);
	struct sw_pool *pool = elem->pool;

	if (pool->cleanup)
		pool->cleanup(elem);

	if (!(pool->flags & SW_POOL_NO_ALLOC))
		kfree(elem);
	atomic_dec(&pool->num_elem);
	sw_pool_put(pool);
}

void *sw_pool_get_index(struct sw_pool *pool, u32 index)
{
	struct rb_node *node = NULL;
	struct sw_pool_entry *elem = NULL;
	unsigned long flags;

	read_lock_irqsave(&pool->pool_lock, flags);

	if (pool->state != SW_POOL_STATE_VALID)
		goto out;

	node = pool->tree.rb_node;

	while (node) {
		elem = rb_entry(node, struct sw_pool_entry, node);

		if (elem->index > index)
			node = node->rb_left;
		else if (elem->index < index)
			node = node->rb_right;
		else {
			kref_get(&elem->ref_cnt);
			break;
		}
	}

out:
	read_unlock_irqrestore(&pool->pool_lock, flags);
	return node ? elem : NULL;
}

void *sw_pool_get_key(struct sw_pool *pool, void *key)
{
	struct rb_node *node = NULL;
	struct sw_pool_entry *elem = NULL;
	int cmp;
	unsigned long flags;

	read_lock_irqsave(&pool->pool_lock, flags);

	if (pool->state != SW_POOL_STATE_VALID)
		goto out;

	node = pool->tree.rb_node;

	while (node) {
		elem = rb_entry(node, struct sw_pool_entry, node);

		cmp = memcmp((u8 *)elem + pool->key_offset,
			     key, pool->key_size);

		if (cmp > 0)
			node = node->rb_left;
		else if (cmp < 0)
			node = node->rb_right;
		else
			break;
	}

	if (node)
		kref_get(&elem->ref_cnt);

out:
	read_unlock_irqrestore(&pool->pool_lock, flags);
	return node ? elem : NULL;
}
