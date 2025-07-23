// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
 * Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.
 */

#include "sw.h"
#include "sw_loc.h"

/*
 * lfsr (linear feedback shift register) with period 255
 */
static u8 sw_get_key(void)
{
	static u32 key = 1;

	key = key << 1;

	key |= (0 != (key & 0x100)) ^ (0 != (key & 0x10))
		^ (0 != (key & 0x80)) ^ (0 != (key & 0x40));

	key &= 0xff;

	return key;
}

int mem_check_range(struct sw_mem *mem, u64 iova, size_t length)
{
	switch (mem->type) {
	case SW_MEM_TYPE_DMA:
		return 0;

	case SW_MEM_TYPE_MR:
	case SW_MEM_TYPE_FMR:
		if (iova < mem->iova ||
		    length > mem->length ||
		    iova > mem->iova + mem->length - length)
			return -EFAULT;
		return 0;

	default:
		return -EFAULT;
	}
}

#define IB_ACCESS_REMOTE	(IB_ACCESS_REMOTE_READ		\
				| IB_ACCESS_REMOTE_WRITE	\
				| IB_ACCESS_REMOTE_ATOMIC)

static void sw_mem_init(int access, struct sw_mem *mem)
{
	u32 lkey = mem->pelem.index << 8 | sw_get_key();
	u32 rkey = (access & IB_ACCESS_REMOTE) ? lkey : 0;

	mem->ibmr.lkey		= lkey;
	mem->ibmr.rkey		= rkey;
	mem->state		= SW_MEM_STATE_INVALID;
	mem->type		= SW_MEM_TYPE_NONE;
	mem->map_shift		= ilog2(SW_BUF_PER_MAP);
}

void sw_mem_cleanup(struct sw_pool_entry *arg)
{
	struct sw_mem *mem = container_of(arg, typeof(*mem), pelem);
	int i;

	if (mem->umem)
		ib_umem_release(mem->umem);

	if (mem->map) {
		for (i = 0; i < mem->num_map; i++)
			kfree(mem->map[i]);

		kfree(mem->map);
	}
}

static int sw_mem_alloc(struct sw_mem *mem, int num_buf)
{
	int i;
	int num_map;
	struct sw_map **map = mem->map;

	num_map = (num_buf + SW_BUF_PER_MAP - 1) / SW_BUF_PER_MAP;

	mem->map = kmalloc_array(num_map, sizeof(*map), GFP_KERNEL);
	if (!mem->map)
		goto err1;

	for (i = 0; i < num_map; i++) {
		mem->map[i] = kmalloc(sizeof(**map), GFP_KERNEL);
		if (!mem->map[i])
			goto err2;
	}

	BUILD_BUG_ON(!is_power_of_2(SW_BUF_PER_MAP));

	mem->map_shift	= ilog2(SW_BUF_PER_MAP);
	mem->map_mask	= SW_BUF_PER_MAP - 1;

	mem->num_buf = num_buf;
	mem->num_map = num_map;
	mem->max_buf = num_map * SW_BUF_PER_MAP;

	return 0;

err2:
	for (i--; i >= 0; i--)
		kfree(mem->map[i]);

	kfree(mem->map);
err1:
	return -ENOMEM;
}

void sw_mem_init_dma(struct sw_pd *pd,
		      int access, struct sw_mem *mem)
{
	sw_mem_init(access, mem);

	mem->ibmr.pd		= &pd->ibpd;
	mem->access		= access;
	mem->state		= SW_MEM_STATE_VALID;
	mem->type		= SW_MEM_TYPE_DMA;
}

int sw_mem_init_fast(struct sw_pd *pd,
		      int max_pages, struct sw_mem *mem)
{
	int err;

	sw_mem_init(0, mem);

	/* In fastreg, we also set the rkey */
	mem->ibmr.rkey = mem->ibmr.lkey;

	err = sw_mem_alloc(mem, max_pages);
	if (err)
		goto err1;

	mem->ibmr.pd		= &pd->ibpd;
	mem->max_buf		= max_pages;
	mem->state		= SW_MEM_STATE_FREE;
	mem->type		= SW_MEM_TYPE_MR;

	return 0;

err1:
	return err;
}

static void lookup_iova(
	struct sw_mem	*mem,
	u64			iova,
	int			*m_out,
	int			*n_out,
	size_t			*offset_out)
{
	size_t			offset = iova - mem->iova + mem->offset;
	int			map_index;
	int			buf_index;
	u64			length;

	if (likely(mem->page_shift)) {
		*offset_out = offset & mem->page_mask;
		offset >>= mem->page_shift;
		*n_out = offset & mem->map_mask;
		*m_out = offset >> mem->map_shift;
	} else {
		map_index = 0;
		buf_index = 0;

		length = mem->map[map_index]->buf[buf_index].size;

		while (offset >= length) {
			offset -= length;
			buf_index++;

			if (buf_index == SW_BUF_PER_MAP) {
				map_index++;
				buf_index = 0;
			}
			length = mem->map[map_index]->buf[buf_index].size;
		}

		*m_out = map_index;
		*n_out = buf_index;
		*offset_out = offset;
	}
}

void *iova_to_vaddr(struct sw_mem *mem, u64 iova, int length)
{
	size_t offset;
	int m, n;
	void *addr;

	if (mem->state != SW_MEM_STATE_VALID) {
		pr_warn("mem not in valid state\n");
		addr = NULL;
		goto out;
	}

	if (!mem->map) {
		addr = (void *)(uintptr_t)iova;
		goto out;
	}

	if (mem_check_range(mem, iova, length)) {
		pr_warn("range violation\n");
		addr = NULL;
		goto out;
	}

	lookup_iova(mem, iova, &m, &n, &offset);

	if (offset + length > mem->map[m]->buf[n].size) {
		pr_warn("crosses page boundary\n");
		addr = NULL;
		goto out;
	}

	addr = (void *)(uintptr_t)mem->map[m]->buf[n].addr + offset;

out:
	return addr;
}

/* copy data from a range (vaddr, vaddr+length-1) to or from
 * a mem object starting at iova. Compute incremental value of
 * crc32 if crcp is not zero. caller must hold a reference to mem
 */
int sw_mem_copy(struct sw_mem *mem, u64 iova, void *addr, int length,
		 enum copy_direction dir, u32 *crcp)
{
	int			err;
	int			bytes;
	u8			*va;
	struct sw_map		**map;
	struct sw_phys_buf	*buf;
	int			m;
	int			i;
	size_t			offset;
	u32			crc = crcp ? (*crcp) : 0;

	if (length == 0)
		return 0;

	iova = (u64)phys_to_virt(iova);
	if (mem->type == SW_MEM_TYPE_DMA) {
		u8 *src, *dest;

		src  = (dir == to_mem_obj) ?
			addr : ((void *)(uintptr_t)iova);

		dest = (dir == to_mem_obj) ?
			((void *)(uintptr_t)iova) : addr;

		memcpy(dest, src, length);

		if (crcp)
			*crcp = sw_crc32(to_rdev(mem->ibmr.device),
					*crcp, dest, length);

		return 0;
	}

	WARN_ON_ONCE(!mem->map);

	err = mem_check_range(mem, iova, length);
	if (err) {
		err = -EFAULT;
		goto err1;
	}

	lookup_iova(mem, iova, &m, &i, &offset);

	map	= mem->map + m;
	buf	= map[0]->buf + i;

	while (length > 0) {
		u8 *src, *dest;

		va	= (u8 *)(uintptr_t)buf->addr + offset;
		src  = (dir == to_mem_obj) ? addr : va;
		dest = (dir == to_mem_obj) ? va : addr;

		bytes	= buf->size - offset;

		if (bytes > length)
			bytes = length;

		memcpy(dest, src, bytes);

		if (crcp)
			crc = sw_crc32(to_rdev(mem->ibmr.device),
					crc, dest, bytes);

		length	-= bytes;
		addr	+= bytes;

		offset	= 0;
		buf++;
		i++;

		if (i == SW_BUF_PER_MAP) {
			i = 0;
			map++;
			buf = map[0]->buf;
		}
	}

	if (crcp)
		*crcp = crc;

	return 0;

err1:
	return err;
}

/* copy data in or out of a wqe, i.e. sg list
 * under the control of a dma descriptor
 */
int copy_data(
	struct sw_pd		*pd,
	int			access,
	struct sw_dma_info	*dma,
	void			*addr,
	int			length,
	enum copy_direction	dir,
	u32			*crcp)
{
	int			bytes;
	struct sw_sge		*sge	= &dma->sge[dma->cur_sge];
	int			offset	= dma->sge_offset;
	int			resid	= dma->resid;
	struct sw_mem		*mem	= NULL;
	u64			iova;
	int			err;

	if (length == 0)
		return 0;

	if (length > resid) {
		err = -EINVAL;
		goto err2;
	}

	if (sge->length && (offset < sge->length)) {
		mem = lookup_mem(pd, access, sge->lkey, lookup_local);
		if (!mem) {
			err = -EINVAL;
			goto err1;
		}
	}

	while (length > 0) {
		bytes = length;

		if (offset >= sge->length) {
			if (mem) {
				sw_drop_ref(mem);
				mem = NULL;
			}
			sge++;
			dma->cur_sge++;
			offset = 0;

			if (dma->cur_sge >= dma->num_sge) {
				err = -ENOSPC;
				goto err2;
			}

			if (sge->length) {
				mem = lookup_mem(pd, access, sge->lkey,
						 lookup_local);
				if (!mem) {
					err = -EINVAL;
					goto err1;
				}
			} else {
				continue;
			}
		}

		if (bytes > sge->length - offset)
			bytes = sge->length - offset;

		if (bytes > 0) {
			iova = sge->addr + offset;

			err = sw_mem_copy(mem, iova, addr, bytes, dir, crcp);
			if (err)
				goto err2;

			offset	+= bytes;
			resid	-= bytes;
			length	-= bytes;
			addr	+= bytes;
		}
	}

	dma->sge_offset = offset;
	dma->resid	= resid;

	if (mem)
		sw_drop_ref(mem);

	return 0;

err2:
	if (mem)
		sw_drop_ref(mem);
err1:
	return err;
}

int advance_dma_data(struct sw_dma_info *dma, unsigned int length)
{
	struct sw_sge		*sge	= &dma->sge[dma->cur_sge];
	int			offset	= dma->sge_offset;
	int			resid	= dma->resid;

	while (length) {
		unsigned int bytes;

		if (offset >= sge->length) {
			sge++;
			dma->cur_sge++;
			offset = 0;
			if (dma->cur_sge >= dma->num_sge)
				return -ENOSPC;
		}

		bytes = length;

		if (bytes > sge->length - offset)
			bytes = sge->length - offset;

		offset	+= bytes;
		resid	-= bytes;
		length	-= bytes;
	}

	dma->sge_offset = offset;
	dma->resid	= resid;

	return 0;
}

/* (1) find the mem (mr or mw) corresponding to lkey/rkey
 *     depending on lookup_type
 * (2) verify that the (qp) pd matches the mem pd
 * (3) verify that the mem can support the requested access
 * (4) verify that mem state is valid
 */
struct sw_mem *lookup_mem(struct sw_pd *pd, int access, u32 key,
			   enum lookup_type type)
{
	struct sw_mem *mem;
	struct sw_dev *sw = to_rdev(pd->ibpd.device);
	int index = key >> 8;

	if ((key & 0xffff0000) == 0x4ac00000) {
		key = pd->ibpd.local_dma_lkey;
		index = key >> 8;
	}
	mem = sw_pool_get_index(&sw->mr_pool, index);
	if (!mem)
		return NULL;

	if (unlikely((type == lookup_local && mr_lkey(mem) != key) ||
		     (type == lookup_remote && mr_rkey(mem) != key) ||
		     mr_pd(mem) != pd ||
		     (access && !(access & mem->access)) ||
		     mem->state != SW_MEM_STATE_VALID)) {
		sw_drop_ref(mem);
		mem = NULL;
	}

	return mem;
}
