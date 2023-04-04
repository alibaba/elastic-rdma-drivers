// SPDX-License-Identifier: GPL-2.0

/* Authors: Cheng Xu <chengyou@linux.alibaba.com> */
/*          Kai Shen <kaishen@linux.alibaba.com> */
/* Copyright (c) 2020-2022, Alibaba Group. */

/* Authors: Bernard Metzler <bmt@zurich.ibm.com> */
/* Copyright (c) 2008-2019, IBM Corporation */

/* Copyright (c) 2013-2015, Mellanox Technologies. All rights reserved. */

#include "kcompat.h"

#include <linux/etherdevice.h>
#include <linux/vmalloc.h>
#include <net/addrconf.h>
#include <rdma/ib_cache.h>
#include <rdma/ib_umem.h>
#ifdef HAVE_UDATA_TO_DRV_CONTEXT
#include <rdma/uverbs_ioctl.h>
#endif

#include "erdma.h"
#include "erdma-abi.h"
#include "erdma_cm.h"
#include "erdma_verbs.h"

extern bool compat_mode;
extern bool rand_qpn;

static int create_qp_cmd(struct erdma_dev *dev, struct erdma_qp *qp,
			 bool is_user)
{
	struct erdma_cmdq_create_qp_req req;
	struct erdma_pd *pd = to_epd(qp->ibqp.pd);
	struct erdma_uqp *user_qp;
	u64 resp0, resp1;
	int err;

	erdma_cmdq_build_reqhdr(&req.hdr, CMDQ_SUBMOD_RDMA,
				CMDQ_OPCODE_CREATE_QP);

	req.cfg0 = FIELD_PREP(ERDMA_CMD_CREATE_QP_SQ_DEPTH_MASK,
			      ilog2(qp->attrs.sq_size)) |
		   FIELD_PREP(ERDMA_CMD_CREATE_QP_QPN_MASK, QP_ID(qp));
	req.cfg1 = FIELD_PREP(ERDMA_CMD_CREATE_QP_RQ_DEPTH_MASK,
			      ilog2(qp->attrs.rq_size)) |
		   FIELD_PREP(ERDMA_CMD_CREATE_QP_PD_MASK, pd->pdn);

	if (!is_user) {
		u32 pgsz_range = ilog2(SZ_1M) - ERDMA_HW_PAGE_SHIFT;

		req.sq_cqn_mtt_cfg =
			FIELD_PREP(ERDMA_CMD_CREATE_QP_PAGE_SIZE_MASK,
				   pgsz_range) |
			FIELD_PREP(ERDMA_CMD_CREATE_QP_CQN_MASK, qp->scq->cqn);
		req.rq_cqn_mtt_cfg =
			FIELD_PREP(ERDMA_CMD_CREATE_QP_PAGE_SIZE_MASK,
				   pgsz_range) |
			FIELD_PREP(ERDMA_CMD_CREATE_QP_CQN_MASK, qp->rcq->cqn);

		req.sq_mtt_cfg =
			FIELD_PREP(ERDMA_CMD_CREATE_QP_PAGE_OFFSET_MASK, 0) |
			FIELD_PREP(ERDMA_CMD_CREATE_QP_MTT_CNT_MASK, 1) |
			FIELD_PREP(ERDMA_CMD_CREATE_QP_MTT_TYPE_MASK,
				   ERDMA_MR_INLINE_MTT);
		req.rq_mtt_cfg = req.sq_mtt_cfg;

		req.rq_buf_addr = qp->kern_qp.rq_buf_dma_addr;
		req.sq_buf_addr = qp->kern_qp.sq_buf_dma_addr;
		req.sq_db_info_dma_addr = qp->kern_qp.sq_db_info_dma_addr;
		req.rq_db_info_dma_addr = qp->kern_qp.rq_db_info_dma_addr;
	} else {
		user_qp = &qp->user_qp;
		req.sq_cqn_mtt_cfg = FIELD_PREP(
			ERDMA_CMD_CREATE_QP_PAGE_SIZE_MASK,
			ilog2(user_qp->sq_mtt.page_size) - ERDMA_HW_PAGE_SHIFT);
		req.sq_cqn_mtt_cfg |=
			FIELD_PREP(ERDMA_CMD_CREATE_QP_CQN_MASK, qp->scq->cqn);

		req.rq_cqn_mtt_cfg = FIELD_PREP(
			ERDMA_CMD_CREATE_QP_PAGE_SIZE_MASK,
			ilog2(user_qp->rq_mtt.page_size) - ERDMA_HW_PAGE_SHIFT);
		req.rq_cqn_mtt_cfg |=
			FIELD_PREP(ERDMA_CMD_CREATE_QP_CQN_MASK, qp->rcq->cqn);

		req.sq_mtt_cfg = user_qp->sq_mtt.page_offset;
		req.sq_mtt_cfg |= FIELD_PREP(ERDMA_CMD_CREATE_QP_MTT_CNT_MASK,
					     user_qp->sq_mtt.mtt_nents) |
				  FIELD_PREP(ERDMA_CMD_CREATE_QP_MTT_TYPE_MASK,
					     user_qp->sq_mtt.mtt_type);

		req.rq_mtt_cfg = user_qp->rq_mtt.page_offset;
		req.rq_mtt_cfg |= FIELD_PREP(ERDMA_CMD_CREATE_QP_MTT_CNT_MASK,
					     user_qp->rq_mtt.mtt_nents) |
				  FIELD_PREP(ERDMA_CMD_CREATE_QP_MTT_TYPE_MASK,
					     user_qp->rq_mtt.mtt_type);

		req.sq_buf_addr = user_qp->sq_mtt.mtt_entry[0];
		req.rq_buf_addr = user_qp->rq_mtt.mtt_entry[0];

		if (user_qp->sq_mtt.mtt_type == ERDMA_MR_INLINE_MTT) {
			req.sq_mtt_entry[0] = user_qp->sq_mtt.mtt_entry[1];
			req.sq_mtt_entry[1] = user_qp->sq_mtt.mtt_entry[2];
			req.sq_mtt_entry[2] = user_qp->sq_mtt.mtt_entry[3];
		}

		if (user_qp->rq_mtt.mtt_type == ERDMA_MR_INLINE_MTT) {
			req.rq_mtt_entry[0] = user_qp->rq_mtt.mtt_entry[1];
			req.rq_mtt_entry[1] = user_qp->rq_mtt.mtt_entry[2];
			req.rq_mtt_entry[2] = user_qp->rq_mtt.mtt_entry[3];
		}

		req.sq_db_info_dma_addr = user_qp->sq_db_info_dma_addr;
		req.rq_db_info_dma_addr = user_qp->rq_db_info_dma_addr;
	}

	err = erdma_post_cmd_wait(&dev->cmdq, &req, sizeof(req), &resp0,
				  &resp1);
	if (err) {
		dev_err(&dev->pdev->dev,
			"ERROR: err code = %d, cmd of create qp failed.\n",
			err);
		return err;
	}

	qp->attrs.cookie =
		FIELD_GET(ERDMA_CMDQ_CREATE_QP_RESP_COOKIE_MASK, resp0);

	return err;
}

static int regmr_cmd(struct erdma_dev *dev, struct erdma_mr *mr)
{
	struct erdma_cmdq_reg_mr_req req;
	struct erdma_pd *pd = to_epd(mr->ibmr.pd);
	u64 *phy_addr;
	int i;

	erdma_cmdq_build_reqhdr(&req.hdr, CMDQ_SUBMOD_RDMA, CMDQ_OPCODE_REG_MR);

	req.cfg0 = FIELD_PREP(ERDMA_CMD_MR_VALID_MASK, mr->valid) |
		   FIELD_PREP(ERDMA_CMD_MR_KEY_MASK, mr->ibmr.lkey & 0xFF) |
		   FIELD_PREP(ERDMA_CMD_MR_MPT_IDX_MASK, mr->ibmr.lkey >> 8);
	req.cfg1 = FIELD_PREP(ERDMA_CMD_REGMR_PD_MASK, pd->pdn) |
		   FIELD_PREP(ERDMA_CMD_REGMR_TYPE_MASK, mr->type) |
		   FIELD_PREP(ERDMA_CMD_REGMR_RIGHT_MASK, mr->access) |
		   FIELD_PREP(ERDMA_CMD_REGMR_ACC_MODE_MASK, 0);
	req.cfg2 = FIELD_PREP(ERDMA_CMD_REGMR_PAGESIZE_MASK,
			      ilog2(mr->mem.page_size)) |
		   FIELD_PREP(ERDMA_CMD_REGMR_MTT_TYPE_MASK, mr->mem.mtt_type) |
		   FIELD_PREP(ERDMA_CMD_REGMR_MTT_CNT_MASK, mr->mem.page_cnt);

	if (mr->type == ERDMA_MR_TYPE_DMA)
		goto post_cmd;

	if (mr->type == ERDMA_MR_TYPE_NORMAL) {
		req.start_va = mr->mem.va;
		req.size = mr->mem.len;
	}

	if (mr->type == ERDMA_MR_TYPE_FRMR ||
	    mr->mem.mtt_type == ERDMA_MR_INDIRECT_MTT) {
		phy_addr = req.phy_addr;
		*phy_addr = mr->mem.mtt_entry[0];
	} else {
		phy_addr = req.phy_addr;
		for (i = 0; i < mr->mem.mtt_nents; i++)
			*phy_addr++ = mr->mem.mtt_entry[i];
	}

post_cmd:
	return erdma_post_cmd_wait(&dev->cmdq, &req, sizeof(req), NULL, NULL);
}

static int create_cq_cmd(struct erdma_dev *dev, struct erdma_cq *cq,
			 bool is_user)
{
	int err;
	struct erdma_cmdq_create_cq_req req;
	u32 page_size;
	struct erdma_mem *mtt;

	erdma_cmdq_build_reqhdr(&req.hdr, CMDQ_SUBMOD_RDMA,
				CMDQ_OPCODE_CREATE_CQ);

	req.cfg0 = FIELD_PREP(ERDMA_CMD_CREATE_CQ_CQN_MASK, cq->cqn) |
		   FIELD_PREP(ERDMA_CMD_CREATE_CQ_DEPTH_MASK, ilog2(cq->depth));
	req.cfg1 = FIELD_PREP(ERDMA_CMD_CREATE_CQ_EQN_MASK, cq->assoc_eqn);

	if (!is_user) {
		page_size = SZ_32M;
		req.cfg0 |= FIELD_PREP(ERDMA_CMD_CREATE_CQ_PAGESIZE_MASK,
				       ilog2(page_size) - ERDMA_HW_PAGE_SHIFT);
		req.qbuf_addr_l = lower_32_bits(cq->kern_cq.qbuf_dma_addr);
		req.qbuf_addr_h = upper_32_bits(cq->kern_cq.qbuf_dma_addr);

		req.cfg1 |= FIELD_PREP(ERDMA_CMD_CREATE_CQ_MTT_CNT_MASK, 1) |
			    FIELD_PREP(ERDMA_CMD_CREATE_CQ_MTT_TYPE_MASK,
				       ERDMA_MR_INLINE_MTT);

		req.first_page_offset = 0;
		req.cq_db_info_addr =
			cq->kern_cq.qbuf_dma_addr + (cq->depth << CQE_SHIFT);
	} else {
		mtt = &cq->user_cq.qbuf_mtt;
		req.cfg0 |=
			FIELD_PREP(ERDMA_CMD_CREATE_CQ_PAGESIZE_MASK,
				   ilog2(mtt->page_size) - ERDMA_HW_PAGE_SHIFT);
		if (mtt->mtt_nents == 1) {
			req.qbuf_addr_l = lower_32_bits(*(u64 *)mtt->mtt_buf);
			req.qbuf_addr_h = upper_32_bits(*(u64 *)mtt->mtt_buf);
		} else {
			req.qbuf_addr_l = lower_32_bits(mtt->mtt_entry[0]);
			req.qbuf_addr_h = upper_32_bits(mtt->mtt_entry[0]);
		}
		req.cfg1 |= FIELD_PREP(ERDMA_CMD_CREATE_CQ_MTT_CNT_MASK,
				       mtt->mtt_nents);
		req.cfg1 |= FIELD_PREP(ERDMA_CMD_CREATE_CQ_MTT_TYPE_MASK,
				       mtt->mtt_type);

		req.first_page_offset = mtt->page_offset;
		req.cq_db_info_addr = cq->user_cq.db_info_dma_addr;
	}

	err = erdma_post_cmd_wait(&dev->cmdq, &req, sizeof(req), NULL, NULL);
	if (err) {
		dev_err(&dev->pdev->dev,
			"ERROR: err code = %d, cmd of create cq failed.\n",
			err);
		return err;
	}

	return 0;
}

static int erdma_alloc_idx(struct erdma_resource_cb *res_cb)
{
	int idx;
	unsigned long flags;

	spin_lock_irqsave(&res_cb->lock, flags);
	idx = find_next_zero_bit(res_cb->bitmap, res_cb->max_cap,
				 res_cb->next_alloc_idx);
	if (idx == res_cb->max_cap) {
		idx = find_first_zero_bit(res_cb->bitmap, res_cb->max_cap);
		if (idx == res_cb->max_cap) {
			res_cb->next_alloc_idx = 1;
			spin_unlock_irqrestore(&res_cb->lock, flags);
			return -ENOSPC;
		}
	}

	set_bit(idx, res_cb->bitmap);
	res_cb->next_alloc_idx = idx + 1;
	spin_unlock_irqrestore(&res_cb->lock, flags);

	return idx;
}

static inline void erdma_free_idx(struct erdma_resource_cb *res_cb, u32 idx)
{
	unsigned long flags;
	u32 used;

	spin_lock_irqsave(&res_cb->lock, flags);
	used = __test_and_clear_bit(idx, res_cb->bitmap);
	spin_unlock_irqrestore(&res_cb->lock, flags);
	WARN_ON(!used);
}

#ifndef HAVE_CORE_MMAP_XA
/*
 * This is only called when the ucontext is destroyed and there can be no
 * concurrent query via mmap or allocate on the database, thus we can be sure no
 * other thread is using the entry pointer. We also know that all the BAR
 * pages have either been zap'd or munmaped at this point.  Normal pages are
 * refcounted and will be freed at the proper time.
 */
static void mmap_entries_remove_free(struct erdma_dev *dev,
				     struct erdma_ucontext *ucontext)
{
	struct erdma_user_mmap_entry *entry, *tmp;

	list_for_each_entry_safe(entry, tmp, &ucontext->pending_mmaps, list) {
		list_del(&entry->list);
		ibdev_dbg(&dev->ibdev,
			  "mmap: key[%#llx] addr[%#llx] len[%#zx] removed\n",
			  rdma_user_mmap_get_offset(&entry->rdma_entry),
			  entry->address, entry->rdma_entry.npages * PAGE_SIZE);
		kfree(entry);
	}
}

static int mmap_entry_validate(struct erdma_ucontext *ucontext,
			       struct vm_area_struct *vma)
{
	size_t length = vma->vm_end - vma->vm_start;

	if (length % PAGE_SIZE != 0 || !(vma->vm_flags & VM_SHARED)) {
		ibdev_dbg(
			ucontext->ibucontext.device,
			"length[%#zx] is not page size aligned[%#lx] or VM_SHARED is not set [%#lx]\n",
			length, PAGE_SIZE, vma->vm_flags);
		return -EINVAL;
	}

	return 0;
}

struct rdma_user_mmap_entry *
rdma_user_mmap_entry_get(struct ib_ucontext *ibucontext,
			 struct vm_area_struct *vma)
{
	struct erdma_ucontext *ucontext = to_ectx(ibucontext);
	size_t length = vma->vm_end - vma->vm_start;
	struct erdma_user_mmap_entry *entry, *tmp;
	u64 key = vma->vm_pgoff << PAGE_SHIFT;
	int err;

	err = mmap_entry_validate(ucontext, vma);
	if (err)
		return NULL;

	mutex_lock(&ucontext->lock);
	list_for_each_entry_safe(entry, tmp, &ucontext->pending_mmaps, list) {
		if (rdma_user_mmap_get_offset(&entry->rdma_entry) == key &&
		    entry->rdma_entry.npages * PAGE_SIZE == length) {
			ibdev_dbg(
				ibucontext->device,
				"mmap: key[%#llx] addr[%#llx] len[%#zx] removed\n",
				key, entry->address,
				entry->rdma_entry.npages * PAGE_SIZE);
			mutex_unlock(&ucontext->lock);
			return &entry->rdma_entry;
		}
	}
	mutex_unlock(&ucontext->lock);

	return NULL;
}
#endif /* !defined (HAVE_CORE_MMAP_XA) */

#ifdef HAVE_CORE_MMAP_XA
static struct rdma_user_mmap_entry *
erdma_user_mmap_entry_insert(struct ib_ucontext *uctx, u64 address, u32 size,
			     u8 mmap_flag, u64 *mmap_offset)
{
	struct erdma_user_mmap_entry *entry =
		kzalloc(sizeof(*entry), GFP_KERNEL);
	int ret;

	if (!entry)
		return NULL;

	entry->address = (u64)address;
	entry->mmap_flag = mmap_flag;

	size = PAGE_ALIGN(size);

	ret = rdma_user_mmap_entry_insert(uctx, &entry->rdma_entry, size);
	if (ret) {
		kfree(entry);
		return NULL;
	}

	*mmap_offset = rdma_user_mmap_get_offset(&entry->rdma_entry);

	return &entry->rdma_entry;
}
#else
static struct rdma_user_mmap_entry *
erdma_user_mmap_entry_insert(struct ib_ucontext *ibucontext, u64 address,
			     size_t length, u8 mmap_flag, u64 *offset)
{
	struct erdma_ucontext *ucontext = to_ectx(ibucontext);
	struct erdma_user_mmap_entry *entry;
	u64 next_mmap_page;

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return NULL;

	entry->address = address;
	entry->rdma_entry.npages = (u32)DIV_ROUND_UP(length, PAGE_SIZE);
	entry->mmap_flag = mmap_flag;

	mutex_lock(&ucontext->lock);
	next_mmap_page = ucontext->mmap_page + (length >> PAGE_SHIFT);
	if (next_mmap_page >= U32_MAX) {
		ibdev_dbg(ucontext->ibucontext.device, "Too many mmap pages\n");
		mutex_unlock(&ucontext->lock);
		kfree(entry);
		return NULL;
	}

	entry->rdma_entry.start_pgoff = ucontext->mmap_page;
	ucontext->mmap_page = next_mmap_page;
	list_add_tail(&entry->list, &ucontext->pending_mmaps);
	mutex_unlock(&ucontext->lock);

	*offset = rdma_user_mmap_get_offset(&entry->rdma_entry);
	ibdev_dbg(ucontext->ibucontext.device,
		  "mmap: addr[%#llx], len[%#zx], key[%#llx] inserted\n",
		  entry->address, entry->rdma_entry.npages * PAGE_SIZE,
		  rdma_user_mmap_get_offset(&entry->rdma_entry));

	return &entry->rdma_entry;
}
#endif

int erdma_query_device(struct ib_device *ibdev, struct ib_device_attr *attr,
		       struct ib_udata *unused)
{
	struct erdma_dev *dev = to_edev(ibdev);

	memset(attr, 0, sizeof(*attr));

	attr->max_mr_size = dev->attrs.max_mr_size;
	attr->vendor_id = PCI_VENDOR_ID_ALIBABA;
	attr->vendor_part_id = dev->pdev->device;
	attr->hw_ver = dev->pdev->revision;
	attr->max_qp = dev->attrs.max_qp - 1;
	attr->max_qp_wr = min(dev->attrs.max_send_wr, dev->attrs.max_recv_wr);
	attr->max_qp_rd_atom = dev->attrs.max_ord;
	attr->max_qp_init_rd_atom = dev->attrs.max_ird;
	attr->max_res_rd_atom = dev->attrs.max_qp * dev->attrs.max_ird;
#ifdef HAVE_NEW_DEVICE_CAP_FLAGS
	attr->device_cap_flags = IB_DEVICE_MEM_MGT_EXTENSIONS;
	attr->kernel_cap_flags = IBK_LOCAL_DMA_LKEY;
#else
	attr->device_cap_flags =
		IB_DEVICE_LOCAL_DMA_LKEY | IB_DEVICE_MEM_MGT_EXTENSIONS;
#endif
	ibdev->local_dma_lkey = dev->attrs.local_dma_key;
#ifdef HAVE_MAX_SEND_RCV_SGE
	attr->max_send_sge = dev->attrs.max_send_sge;
	attr->max_recv_sge = dev->attrs.max_recv_sge;
#else
	attr->max_sge = dev->attrs.max_send_sge;
#endif
	attr->max_sge_rd = dev->attrs.max_sge_rd;
	attr->max_cq = dev->attrs.max_cq - 1;
	attr->max_cqe = dev->attrs.max_cqe;
	attr->max_mr = dev->attrs.max_mr;
	attr->max_pd = dev->attrs.max_pd;
	attr->max_mw = dev->attrs.max_mw;
	attr->max_fast_reg_page_list_len = ERDMA_MAX_FRMR_PA;
	attr->page_size_cap = ERDMA_PAGE_SIZE_SUPPORT;

	if (dev->attrs.flags & ERDMA_DEV_CAP_FLAGS_ATOMIC) {
		attr->atomic_cap = IB_ATOMIC_GLOB;
		attr->masked_atomic_cap = IB_ATOMIC_GLOB;
	}

	attr->fw_ver = ((u64)(dev->attrs.fw_version >> 16) << 32) |
		       (((dev->attrs.fw_version >> 8) & 0xFF) << 16) |
		       ((dev->attrs.fw_version & 0xFF));

	if (dev->netdev)
		addrconf_addr_eui48((u8 *)&attr->sys_image_guid,
				    dev->netdev->dev_addr);

	return 0;
}

int erdma_query_gid(struct ib_device *ibdev, port_t port, int idx,
		    union ib_gid *gid)
{
	struct erdma_dev *dev = to_edev(ibdev);

	memset(gid, 0, sizeof(*gid));
	ether_addr_copy(gid->raw, dev->attrs.peer_addr);

	return 0;
}

int erdma_query_port(struct ib_device *ibdev, port_t port,
		     struct ib_port_attr *attr)
{
	struct erdma_dev *dev = to_edev(ibdev);

	memset(attr, 0, sizeof(*attr));

	attr->state = dev->state;
	if (dev->netdev) {
		attr->active_speed = IB_SPEED_EDR;
		attr->active_width = IB_WIDTH_4X;
		attr->max_mtu = ib_mtu_int_to_enum(dev->netdev->mtu);
		attr->active_mtu = ib_mtu_int_to_enum(dev->netdev->mtu);
	}

	if (compat_mode)
		attr->gid_tbl_len = 16;
	else
		attr->gid_tbl_len = 1;
	attr->pkey_tbl_len = 1;
	attr->port_cap_flags = IB_PORT_CM_SUP | IB_PORT_DEVICE_MGMT_SUP;
	attr->max_msg_sz = -1;
	if (dev->state == IB_PORT_ACTIVE)
		attr->phys_state = IB_PORT_PHYS_STATE_LINK_UP;
	else
		attr->phys_state = IB_PORT_PHYS_STATE_DISABLED;

	return 0;
}

int erdma_get_port_immutable(struct ib_device *ibdev, port_t port,
			     struct ib_port_immutable *port_immutable)
{
	if (compat_mode) {
		port_immutable->gid_tbl_len = 16;
		port_immutable->core_cap_flags =
			RDMA_CORE_PORT_IBA_ROCE_UDP_ENCAP;
		port_immutable->max_mad_size = IB_MGMT_MAD_SIZE;
	} else {
		port_immutable->gid_tbl_len = 1;
		port_immutable->core_cap_flags = RDMA_CORE_PORT_IWARP;
	}

	return 0;
}

int erdma_query_pkey(struct ib_device *ibdev, port_t port, u16 index, u16 *pkey)
{
	if (index > 0)
		return -EINVAL;

	*pkey = 0xffff;
	return 0;
}

enum rdma_link_layer erdma_get_link_layer(struct ib_device *dev,
					  port_t port_num)
{
	return IB_LINK_LAYER_ETHERNET;
}

#ifdef HAVE_OLD_GID_OPERATION
int erdma_add_gid(const struct ib_gid_attr *attr, void **context)
#else
int erdma_add_gid(struct ib_device *device, u8 port_num, unsigned int index,
		  const union ib_gid *gid, const struct ib_gid_attr *attr,
		  void **context)
#endif
{
	return 0;
}

#ifdef HAVE_OLD_GID_OPERATION
int erdma_del_gid(const struct ib_gid_attr *attr, void **context)
#else
int erdma_del_gid(struct ib_device *device, u8 port_num, unsigned int index,
		  void **context)
#endif
{
	return 0;
}

int erdma_alloc_pd(struct ib_pd *ibpd, struct ib_udata *udata)
{
	struct erdma_pd *pd = to_epd(ibpd);
	struct erdma_dev *dev = to_edev(ibpd->device);
	int pdn;

	ERDMA_INC_CNT(dev, CMD_ALLOC_PD);

	pdn = erdma_alloc_idx(&dev->res_cb[ERDMA_RES_TYPE_PD]);
	if (pdn < 0) {
		ERDMA_INC_CNT(dev, CMD_ALLOC_PD_FAILED);
		return pdn;
	}

	pd->pdn = pdn;

	return 0;
}

#ifndef HAVE_PD_CORE_ALLOCATION
struct ib_pd *erdma_kzalloc_pd(struct ib_device *ibdev,
			       struct ib_ucontext *ibucontext,
			       struct ib_udata *udata)
{
	struct erdma_pd *pd;
	int ret;

	pd = kzalloc(sizeof(*pd), GFP_KERNEL);
	if (!pd)
		return ERR_PTR(-ENOMEM);

	pd->ibpd.device = ibdev;

	ret = erdma_alloc_pd(&pd->ibpd, udata);
	if (ret)
		goto out_free;

	return &pd->ibpd;

out_free:
	kfree(pd);

	return ERR_PTR(ret);
}
#endif

#ifdef HAVE_DEALLOC_PD_UDATA_RC
int erdma_dealloc_pd(struct ib_pd *ibpd, struct ib_udata *udata)
#elif defined(HAVE_DEALLOC_PD_UDATA)
void erdma_dealloc_pd(struct ib_pd *ibpd, struct ib_udata *udata)
#else
int erdma_dealloc_pd(struct ib_pd *ibpd)
#endif
{
	struct erdma_dev *dev = to_edev(ibpd->device);
	struct erdma_pd *pd = to_epd(ibpd);

	ERDMA_INC_CNT(dev, CMD_DEALLOC_PD);

	erdma_free_idx(&dev->res_cb[ERDMA_RES_TYPE_PD], pd->pdn);
#ifndef HAVE_PD_CORE_ALLOCATION
	kfree(pd);
#endif
#ifndef HAVE_DEALLOC_PD_UDATA
	return 0;
#endif
}

static void erdma_flush_worker(struct work_struct *work)
{
	struct delayed_work *dwork = to_delayed_work(work);
	struct erdma_qp *qp =
		container_of(dwork, struct erdma_qp, reflush_dwork);
	struct erdma_cmdq_reflush_req req;

	erdma_cmdq_build_reqhdr(&req.hdr, CMDQ_SUBMOD_RDMA,
				CMDQ_OPCODE_REFLUSH);
	req.qpn = QP_ID(qp);
	req.sq_pi = qp->kern_qp.sq_pi;
	req.rq_pi = qp->kern_qp.rq_pi;
	erdma_post_cmd_wait(&qp->dev->cmdq, &req, sizeof(req), NULL, NULL);
}

static int erdma_qp_validate_cap(struct erdma_dev *dev,
				 struct ib_qp_init_attr *attrs)
{
	if ((attrs->cap.max_send_wr > dev->attrs.max_send_wr) ||
	    (attrs->cap.max_recv_wr > dev->attrs.max_recv_wr) ||
	    (attrs->cap.max_send_sge > dev->attrs.max_send_sge) ||
	    (attrs->cap.max_recv_sge > dev->attrs.max_recv_sge) ||
	    (attrs->cap.max_inline_data > ERDMA_MAX_INLINE) ||
	    !attrs->cap.max_send_wr || !attrs->cap.max_recv_wr) {
		return -EINVAL;
	}

	return 0;
}

static int erdma_qp_validate_attr(struct erdma_dev *dev,
				  struct ib_qp_init_attr *attrs)
{
	if (attrs->qp_type != IB_QPT_RC)
		return -EOPNOTSUPP;

	if (attrs->srq)
		return -EOPNOTSUPP;

	if (!attrs->send_cq || !attrs->recv_cq)
		return -EOPNOTSUPP;

	return 0;
}

static void free_kernel_qp(struct erdma_qp *qp)
{
	struct erdma_dev *dev = qp->dev;

	vfree(qp->kern_qp.swr_tbl);
	vfree(qp->kern_qp.rwr_tbl);

	if (qp->kern_qp.sq_buf)
		dma_free_coherent(&dev->pdev->dev,
				  qp->attrs.sq_size << SQEBB_SHIFT,
				  qp->kern_qp.sq_buf,
				  qp->kern_qp.sq_buf_dma_addr);

	if (qp->kern_qp.rq_buf)
		dma_free_coherent(&dev->pdev->dev,
				  qp->attrs.rq_size << RQE_SHIFT,
				  qp->kern_qp.rq_buf,
				  qp->kern_qp.rq_buf_dma_addr);

	if (qp->kern_qp.sq_db_info)
		dma_pool_free(dev->db_pool, qp->kern_qp.sq_db_info,
			      qp->kern_qp.sq_db_info_dma_addr);

	if (qp->kern_qp.rq_db_info)
		dma_pool_free(dev->db_pool, qp->kern_qp.rq_db_info,
			      qp->kern_qp.rq_db_info_dma_addr);
}

static int update_kernel_qp_oob_attr(struct erdma_qp *qp)
{
	struct iw_ext_conn_param *param =
		(struct iw_ext_conn_param *)(qp->ibqp.qp_context);

	if (!qp->attrs.connect_without_cm)
		return -EINVAL;

	if (param == NULL)
		return -EINVAL;

	if (param->sk_addr.family != PF_INET) {
		ibdev_err_ratelimited(
			&qp->dev->ibdev,
			"IPv4 address is required for connection without CM.\n");
		return -EINVAL;
	}
	qp->attrs.sip = ntohl(param->sk_addr.saddr_v4);
	qp->attrs.dip = ntohl(param->sk_addr.daddr_v4);
	qp->attrs.dport = ntohs(param->sk_addr.dport);
	qp->attrs.sport = param->sk_addr.sport;

	return 0;
}

static int init_kernel_qp(struct erdma_dev *dev, struct erdma_qp *qp,
			  struct ib_qp_init_attr *attrs)
{
	struct erdma_kqp *kqp = &qp->kern_qp;
	int ret = -ENOMEM;

	if (attrs->sq_sig_type == IB_SIGNAL_ALL_WR)
		kqp->sig_all = 1;

	kqp->sq_pi = 0;
	kqp->sq_ci = 0;
	kqp->rq_pi = 0;
	kqp->rq_ci = 0;
	kqp->hw_sq_db = dev->func_bar +
			(ERDMA_SDB_SHARED_PAGE_INDEX << ERDMA_HW_PAGE_SHIFT);
	kqp->hw_rq_db = dev->func_bar + ERDMA_BAR_RQDB_SPACE_OFFSET;

	kqp->swr_tbl = vmalloc(qp->attrs.sq_size * sizeof(u64));
	kqp->rwr_tbl = vmalloc(qp->attrs.rq_size * sizeof(u64));
	if (!kqp->swr_tbl || !kqp->rwr_tbl)
		goto err_out;

	kqp->sq_buf = dma_alloc_coherent(&dev->pdev->dev,
					 qp->attrs.sq_size << SQEBB_SHIFT,
					 &kqp->sq_buf_dma_addr, GFP_KERNEL);
	if (!kqp->sq_buf)
		goto err_out;

	kqp->rq_buf = dma_alloc_coherent(&dev->pdev->dev,
					 qp->attrs.rq_size << RQE_SHIFT,
					 &kqp->rq_buf_dma_addr, GFP_KERNEL);
	if (!kqp->rq_buf)
		goto err_out;

	kqp->sq_db_info = dma_pool_alloc(dev->db_pool, GFP_KERNEL,
					 &kqp->sq_db_info_dma_addr);
	if (!kqp->sq_db_info)
		goto err_out;

	kqp->rq_db_info = dma_pool_alloc(dev->db_pool, GFP_KERNEL,
					 &kqp->rq_db_info_dma_addr);
	if (!kqp->rq_db_info)
		goto err_out;

	if (attrs->create_flags & IB_QP_CREATE_IWARP_WITHOUT_CM) {
		struct iw_ext_conn_param *param =
			(struct iw_ext_conn_param *)(attrs->qp_context);

		if (param == NULL) {
			ret = -EINVAL;
			goto err_out;
		}
		if (param->sk_addr.family != PF_INET) {
			ibdev_err_ratelimited(
				&dev->ibdev,
				"IPv4 address is required for connection without CM.\n");
			ret = -EINVAL;
			goto err_out;
		}
		qp->attrs.connect_without_cm = true;
		qp->attrs.sip = ntohl(param->sk_addr.saddr_v4);
		qp->attrs.dip = ntohl(param->sk_addr.daddr_v4);
		qp->attrs.dport = ntohs(param->sk_addr.dport);
		qp->attrs.sport = param->sk_addr.sport;
	}
	spin_lock_init(&kqp->sq_lock);
	spin_lock_init(&kqp->rq_lock);

	return 0;

err_out:
	free_kernel_qp(qp);
	return ret;
}

static int get_mtt_entries(struct ib_udata *udata, struct erdma_ucontext *ctx,
			   struct erdma_mem *mem, u64 start, u64 len,
			   int access, u64 virt, unsigned long req_page_size,
			   u8 force_indirect_mtt, bool is_mr)
{
	struct erdma_dev *dev = to_edev(ctx->ibucontext.device);
#ifdef HAVE_IB_UMEM_FIND_SINGLE_PG_SIZE
	struct ib_block_iter biter;
#else
	int chunk_pages, entry, i;
	struct scatterlist *sg;
	u64 pg_addr;
#endif
	uint64_t *phy_addr = NULL;
	int ret = 0;

#ifdef HAVE_IB_UMEM_GET_PEER
	if (is_mr)
		mem->umem = ib_umem_get_peer(&dev->ibdev, start, len, access,
					     IB_PEER_MEM_INVAL_SUPP);
	else
		mem->umem =
			ib_umem_get_peer(&dev->ibdev, start, len, access, 0);
#elif defined(HAVE_IB_UMEM_GET_DEVICE_PARAM)
	mem->umem = ib_umem_get(&dev->ibdev, start, len, access);
#elif defined(HAVE_IB_UMEM_GET_NO_DMASYNC)
	mem->umem = ib_umem_get(udata, start, len, access);
#elif defined(HAVE_IB_UMEM_GET_UDATA)
	mem->umem = ib_umem_get(udata, start, len, access, 0);
#else
	mem->umem = ib_umem_get(&ctx->ibucontext, start, len, access, 0);
#endif
	if (IS_ERR(mem->umem)) {
		ret = PTR_ERR(mem->umem);
		mem->umem = NULL;
		return ret;
	}

	mem->va = virt;
	mem->len = len;
	mem->page_size = ib_umem_find_best_pgsz(mem->umem, req_page_size, virt);
	mem->page_offset = start & (mem->page_size - 1);
	mem->mtt_nents = ib_umem_num_dma_blocks(mem->umem, mem->page_size);
	mem->page_cnt = mem->mtt_nents;

	if (mem->page_cnt > ERDMA_MAX_INLINE_MTT_ENTRIES ||
	    force_indirect_mtt) {
		mem->mtt_type = ERDMA_MR_INDIRECT_MTT;
		mem->mtt_buf =
			alloc_pages_exact(MTT_SIZE(mem->page_cnt), GFP_KERNEL);
		if (!mem->mtt_buf) {
			ret = -ENOMEM;
			goto error_ret;
		}
		phy_addr = mem->mtt_buf;
	} else {
		mem->mtt_type = ERDMA_MR_INLINE_MTT;
		phy_addr = mem->mtt_entry;
	}

#ifdef HAVE_IB_UMEM_FIND_SINGLE_PG_SIZE
	rdma_umem_for_each_dma_block(mem->umem, &biter, mem->page_size) {
		*phy_addr = rdma_block_iter_dma_address(&biter);
		phy_addr++;
	}
#else
	for_each_sg(mem->umem->sg_head.sgl, sg, mem->umem->nmap, entry) {
		chunk_pages = sg_dma_len(sg) >> PAGE_SHIFT;
		for (i = 0; i < chunk_pages; i++) {
			pg_addr = sg_dma_address(sg) + (i << PAGE_SHIFT);

			if ((entry + i) == 0)
				*phy_addr = pg_addr & PAGE_MASK;
			else if (!(pg_addr & ~PAGE_MASK))
				*phy_addr = pg_addr;
			else
				continue;
			phy_addr++;
		}
	}
#endif
	if (mem->mtt_type == ERDMA_MR_INDIRECT_MTT) {
		mem->mtt_entry[0] =
			dma_map_single(&dev->pdev->dev, mem->mtt_buf,
				       MTT_SIZE(mem->page_cnt), DMA_TO_DEVICE);
		if (dma_mapping_error(&dev->pdev->dev, mem->mtt_entry[0])) {
			free_pages_exact(mem->mtt_buf, MTT_SIZE(mem->page_cnt));
			mem->mtt_buf = NULL;
			ret = -ENOMEM;
			goto error_ret;
		}
	}

	return 0;

error_ret:
	if (mem->umem) {
		ib_umem_release(mem->umem);
		mem->umem = NULL;
	}

	return ret;
}

static void put_mtt_entries(struct erdma_dev *dev, struct erdma_mem *mem)
{
	if (mem->mtt_buf) {
		dma_unmap_single(&dev->pdev->dev, mem->mtt_entry[0],
				 MTT_SIZE(mem->page_cnt), DMA_TO_DEVICE);
		free_pages_exact(mem->mtt_buf, MTT_SIZE(mem->page_cnt));
	}

	if (mem->umem) {
		ib_umem_release(mem->umem);
		mem->umem = NULL;
	}
}

static int erdma_map_user_dbrecords(struct ib_udata *udata,
				    struct erdma_ucontext *uctx,
				    u64 dbrecords_va,
				    struct erdma_user_dbrecords_page **dbr_page,
				    dma_addr_t *dma_addr)
{
	struct erdma_user_dbrecords_page *page = NULL;
	int rv = 0;

	mutex_lock(&uctx->dbrecords_page_mutex);

	list_for_each_entry(page, &uctx->dbrecords_page_list, list)
		if (page->va == (dbrecords_va & PAGE_MASK))
			goto found;

	page = kmalloc(sizeof(*page), GFP_KERNEL);
	if (!page) {
		rv = -ENOMEM;
		goto out;
	}

	page->va = (dbrecords_va & PAGE_MASK);
	page->refcnt = 0;

#ifdef HAVE_IB_UMEM_GET_DEVICE_PARAM
	page->umem = ib_umem_get(uctx->ibucontext.device,
				 dbrecords_va & PAGE_MASK, PAGE_SIZE, 0);
#elif defined(HAVE_IB_UMEM_GET_NO_DMASYNC)
	page->umem = ib_umem_get(udata, dbrecords_va & PAGE_MASK, PAGE_SIZE, 0);
#elif defined(HAVE_IB_UMEM_GET_UDATA)
	page->umem =
		ib_umem_get(udata, dbrecords_va & PAGE_MASK, PAGE_SIZE, 0, 0);
#else
	page->umem = ib_umem_get(&uctx->ibucontext, dbrecords_va & PAGE_MASK,
				 PAGE_SIZE, 0, 0);
#endif
	if (IS_ERR(page->umem)) {
		rv = PTR_ERR(page->umem);
		kfree(page);
		goto out;
	}

	list_add(&page->list, &uctx->dbrecords_page_list);

found:
#ifdef HAVE_UMEM_SGT_APPEND
	*dma_addr = sg_dma_address(page->umem->sgt_append.sgt.sgl) +
		    (dbrecords_va & ~PAGE_MASK);
#else
	*dma_addr = sg_dma_address(page->umem->sg_head.sgl) +
		    (dbrecords_va & ~PAGE_MASK);
#endif
	*dbr_page = page;
	page->refcnt++;

out:
	mutex_unlock(&uctx->dbrecords_page_mutex);
	return rv;
}

static void
erdma_unmap_user_dbrecords(struct erdma_ucontext *ctx,
			   struct erdma_user_dbrecords_page **dbr_page)
{
	if (!ctx || !(*dbr_page))
		return;

	mutex_lock(&ctx->dbrecords_page_mutex);
	if (--(*dbr_page)->refcnt == 0) {
		list_del(&(*dbr_page)->list);
		ib_umem_release((*dbr_page)->umem);
		kfree(*dbr_page);
	}

	*dbr_page = NULL;
	mutex_unlock(&ctx->dbrecords_page_mutex);
}

static int init_user_qp(struct erdma_qp *qp, struct ib_udata *udata,
			struct erdma_ucontext *uctx, u64 va, u32 len,
			u64 db_info_va)
{
	dma_addr_t db_info_dma_addr;
	u32 rq_offset;
	int ret;

	if (len < (ALIGN(qp->attrs.sq_size * SQEBB_SIZE, ERDMA_HW_PAGE_SIZE) +
		   qp->attrs.rq_size * RQE_SIZE))
		return -EINVAL;

	ret = get_mtt_entries(udata, uctx, &qp->user_qp.sq_mtt, va,
			      qp->attrs.sq_size << SQEBB_SHIFT, 0, va,
			      (SZ_1M - SZ_4K), 0, false);
	if (ret)
		return ret;

	rq_offset = ALIGN(qp->attrs.sq_size << SQEBB_SHIFT, ERDMA_HW_PAGE_SIZE);
	qp->user_qp.rq_offset = rq_offset;

	ret = get_mtt_entries(udata, uctx, &qp->user_qp.rq_mtt, va + rq_offset,
			      qp->attrs.rq_size << RQE_SHIFT, 0, va + rq_offset,
			      (SZ_1M - SZ_4K), 0, false);
	if (ret)
		goto put_sq_mtt;

	ret = erdma_map_user_dbrecords(udata, uctx, db_info_va,
				       &qp->user_qp.user_dbr_page,
				       &db_info_dma_addr);
	if (ret)
		goto put_rq_mtt;

	qp->user_qp.sq_db_info_dma_addr = db_info_dma_addr;
	qp->user_qp.rq_db_info_dma_addr = db_info_dma_addr + ERDMA_DB_SIZE;

	return 0;

put_rq_mtt:
	put_mtt_entries(qp->dev, &qp->user_qp.rq_mtt);

put_sq_mtt:
	put_mtt_entries(qp->dev, &qp->user_qp.sq_mtt);

	return ret;
}

static void free_user_qp(struct erdma_qp *qp, struct erdma_ucontext *uctx)
{
	put_mtt_entries(qp->dev, &qp->user_qp.sq_mtt);
	put_mtt_entries(qp->dev, &qp->user_qp.rq_mtt);
	erdma_unmap_user_dbrecords(uctx, &qp->user_qp.user_dbr_page);
}

int erdma_create_qp(struct ib_qp *ibqp, struct ib_qp_init_attr *attrs,
		    struct ib_udata *udata)
{
	struct erdma_dev *dev = to_edev(ibqp->device);
	struct erdma_uresp_create_qp uresp;
	struct erdma_qp *qp = to_eqp(ibqp);
	struct erdma_ureq_create_qp ureq;
	struct erdma_ucontext *uctx;
	u32 next_idx;
	int ret;

#ifdef HAVE_UDATA_TO_DRV_CONTEXT
	uctx = rdma_udata_to_drv_context(udata, struct erdma_ucontext,
					 ibucontext);
#else
	uctx = ibqp->pd->uobject ? to_ectx(ibqp->pd->uobject->context) : NULL;
#endif

	ERDMA_INC_CNT(dev, CMD_CREATE_QP);

	ret = erdma_qp_validate_cap(dev, attrs);
	if (ret)
		goto err_out;

	ret = erdma_qp_validate_attr(dev, attrs);
	if (ret)
		goto err_out;

	qp->scq = to_ecq(attrs->send_cq);
	qp->rcq = to_ecq(attrs->recv_cq);
	qp->dev = dev;
	qp->attrs.cc = dev->attrs.cc;

	init_rwsem(&qp->state_lock);
	kref_init(&qp->ref);
	init_completion(&qp->safe_free);

	if (rand_qpn) {
		get_random_bytes(&next_idx, sizeof(u32));
		dev->next_alloc_qpn = next_idx % dev->attrs.max_qp;
	}
#ifdef HAVE_XARRAY
	ret = xa_alloc_cyclic(&dev->qp_xa, &qp->ibqp.qp_num, qp,
			      XA_LIMIT(1, dev->attrs.max_qp - 1),
			      &dev->next_alloc_qpn, GFP_KERNEL);
#else
	ret = idr_alloc_cyclic_safe(&dev->qp_idr, &qp->ibqp.qp_num, qp,
				    &dev->idr_lock, &dev->next_alloc_qpn,
				    dev->attrs.max_qp);
#endif
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_out;
	}

	qp->attrs.sq_size = roundup_pow_of_two(attrs->cap.max_send_wr *
					       ERDMA_MAX_WQEBB_PER_SQE);
	qp->attrs.rq_size = roundup_pow_of_two(attrs->cap.max_recv_wr);

	if (uctx) {
		ret = ib_copy_from_udata(&ureq, udata,
					 min(sizeof(ureq), udata->inlen));
		if (ret)
			goto err_out_xa;

		ret = init_user_qp(qp, udata, uctx, ureq.qbuf_va, ureq.qbuf_len,
				   ureq.db_record_va);
		if (ret)
			goto err_out_xa;

		memset(&uresp, 0, sizeof(uresp));

		uresp.num_sqe = qp->attrs.sq_size;
		uresp.num_rqe = qp->attrs.rq_size;
		uresp.qp_id = QP_ID(qp);
		uresp.rq_offset = qp->user_qp.rq_offset;

		ret = ib_copy_to_udata(udata, &uresp, sizeof(uresp));
		if (ret)
			goto err_out_cmd;
	} else {
		ret = init_kernel_qp(dev, qp, attrs);
		if (ret)
			goto err_out_xa;
	}

	INIT_DELAYED_WORK(&qp->reflush_dwork, erdma_flush_worker);

	qp->attrs.max_send_sge = attrs->cap.max_send_sge;
	qp->attrs.max_recv_sge = attrs->cap.max_recv_sge;
	qp->attrs.state = ERDMA_QP_STATE_IDLE;

	ret = create_qp_cmd(dev, qp, uctx ? true : false);
	if (ret)
		goto err_out_cmd;

	return 0;

err_out_cmd:
	if (uctx)
		free_user_qp(qp, uctx);
	else
		free_kernel_qp(qp);
err_out_xa:
#ifdef HAVE_XARRAY
	xa_erase(&dev->qp_xa, QP_ID(qp));
#else
	idr_remove_safe(&dev->qp_idr, QP_ID(qp), &dev->idr_lock);
#endif
err_out:
	ERDMA_INC_CNT(dev, CMD_CREATE_QP_FAILED);
	return ret;
}

#ifndef HAVE_QP_CORE_ALLOCATION
struct ib_qp *erdma_kzalloc_qp(struct ib_pd *ibpd,
			       struct ib_qp_init_attr *attrs,
			       struct ib_udata *udata)
{
	struct erdma_qp *qp;
	int ret;
	struct erdma_ucontext *uctx;

#ifdef HAVE_UDATA_TO_DRV_CONTEXT
	uctx = rdma_udata_to_drv_context(udata, struct erdma_ucontext,
					 ibucontext);
#else
	uctx = ibpd->uobject ? to_ectx(ibpd->uobject->context) : NULL;
#endif

	qp = kzalloc(sizeof(*qp), GFP_KERNEL);
	if (!qp) {
		ret = -ENOMEM;
		goto err_out;
	}

#ifdef HAVE_RDMA_RESTRACK_ENTRY_USER
	qp->ibqp.res.user = uctx ? 1 : 0;
#else
	qp->user = uctx ? 1 : 0;
#ifdef HAVE_IB_CQ_WITH_RES
	qp->ibqp.res.task = uctx ? current : NULL;
#endif
#endif

	qp->ibqp.device = ibpd->device;
	qp->ibqp.pd = ibpd;
	qp->ibqp.qp_type = attrs->qp_type;

	ret = erdma_create_qp(&qp->ibqp, attrs, udata);
	if (ret)
		goto err_free;

		/* clear the field, otherwise core code will have problems. */
#ifdef HAVE_IB_CQ_WITH_RES
	qp->ibqp.res.task = NULL;
#endif
	return &qp->ibqp;
err_free:
	kfree(qp);
err_out:
	return ERR_PTR(ret);
}
#endif

static int erdma_create_stag(struct erdma_dev *dev, u32 *stag)
{
	int stag_idx;

	stag_idx = erdma_alloc_idx(&dev->res_cb[ERDMA_RES_TYPE_STAG_IDX]);
	if (stag_idx < 0)
		return stag_idx;

	/* For now, we always let key field be zero. */
	*stag = (stag_idx << 8);

	return 0;
}

struct ib_mr *erdma_get_dma_mr(struct ib_pd *ibpd, int acc)
{
	struct erdma_mr *mr;
	struct erdma_dev *dev = to_edev(ibpd->device);
	int ret;
	u32 stag;

	ERDMA_INC_CNT(dev, CMD_GET_DMA_MR);

	mr = kzalloc(sizeof(*mr), GFP_KERNEL);
	if (!mr) {
		ERDMA_INC_CNT(dev, CMD_GET_DMA_MR_FAILED);
		return ERR_PTR(-ENOMEM);
	}
	ret = erdma_create_stag(dev, &stag);
	if (ret)
		goto out_free;

	mr->type = ERDMA_MR_TYPE_DMA;

	mr->ibmr.lkey = stag;
	mr->ibmr.rkey = stag;
	mr->ibmr.pd = ibpd;
	mr->access = ERDMA_MR_ACC_LR | to_erdma_access_flags(acc);
	ret = regmr_cmd(dev, mr);
	if (ret) {
		ret = -EIO;
		goto out_remove_stag;
	}

	return &mr->ibmr;

out_remove_stag:
	erdma_free_idx(&dev->res_cb[ERDMA_RES_TYPE_STAG_IDX],
		       mr->ibmr.lkey >> 8);

out_free:
	kfree(mr);

	ERDMA_INC_CNT(dev, CMD_GET_DMA_MR_FAILED);
	return ERR_PTR(ret);
}

#ifndef HAVE_ALLOC_MR_NO_UDATA
struct ib_mr *erdma_ib_alloc_mr(struct ib_pd *ibpd, enum ib_mr_type mr_type,
				u32 max_num_sg, struct ib_udata *udata)
#else
struct ib_mr *erdma_ib_alloc_mr(struct ib_pd *ibpd, enum ib_mr_type mr_type,
				u32 max_num_sg)
#endif
{
	struct erdma_mr *mr;
	struct erdma_dev *dev = to_edev(ibpd->device);
	int ret;
	u32 stag;

	ERDMA_INC_CNT(dev, CMD_ALLOC_MR);

	if (mr_type != IB_MR_TYPE_MEM_REG) {
		ERDMA_INC_CNT(dev, CMD_ALLOC_MR_FAILED);
		return ERR_PTR(-EOPNOTSUPP);
	}

	if (max_num_sg > ERDMA_MR_MAX_MTT_CNT) {
		ibdev_err(&dev->ibdev, "max_num_sg too large:%u", max_num_sg);
		ERDMA_INC_CNT(dev, CMD_ALLOC_MR_FAILED);
		return ERR_PTR(-EINVAL);
	}

	mr = kzalloc(sizeof(*mr), GFP_KERNEL);
	if (!mr) {
		ERDMA_INC_CNT(dev, CMD_ALLOC_MR_FAILED);
		return ERR_PTR(-ENOMEM);
	}

	ret = erdma_create_stag(dev, &stag);
	if (ret)
		goto out_free;

	mr->type = ERDMA_MR_TYPE_FRMR;

	mr->ibmr.lkey = stag;
	mr->ibmr.rkey = stag;
	mr->ibmr.pd = ibpd;
	/* update it in FRMR. */
	mr->access = ERDMA_MR_ACC_LR | ERDMA_MR_ACC_LW | ERDMA_MR_ACC_RR |
		     ERDMA_MR_ACC_RW;

	mr->mem.page_size = PAGE_SIZE; /* update it later. */
	mr->mem.page_cnt = max_num_sg;
	mr->mem.mtt_type = ERDMA_MR_INDIRECT_MTT;
	mr->mem.mtt_buf =
		alloc_pages_exact(MTT_SIZE(mr->mem.page_cnt), GFP_KERNEL);
	if (!mr->mem.mtt_buf) {
		ret = -ENOMEM;
		goto out_remove_stag;
	}

	mr->mem.mtt_entry[0] =
		dma_map_single(&dev->pdev->dev, mr->mem.mtt_buf,
			       MTT_SIZE(mr->mem.page_cnt), DMA_TO_DEVICE);
	if (dma_mapping_error(&dev->pdev->dev, mr->mem.mtt_entry[0])) {
		ret = -ENOMEM;
		goto out_free_mtt;
	}

	ret = regmr_cmd(dev, mr);
	if (ret) {
		ret = -EIO;
		goto out_dma_unmap;
	}

	return &mr->ibmr;

out_dma_unmap:
	dma_unmap_single(&dev->pdev->dev, mr->mem.mtt_entry[0],
			 MTT_SIZE(mr->mem.page_cnt), DMA_TO_DEVICE);
out_free_mtt:
	free_pages_exact(mr->mem.mtt_buf, MTT_SIZE(mr->mem.page_cnt));

out_remove_stag:
	erdma_free_idx(&dev->res_cb[ERDMA_RES_TYPE_STAG_IDX],
		       mr->ibmr.lkey >> 8);

out_free:
	kfree(mr);

	ERDMA_INC_CNT(dev, CMD_ALLOC_MR_FAILED);

	return ERR_PTR(ret);
}

static int erdma_set_page(struct ib_mr *ibmr, u64 addr)
{
	struct erdma_mr *mr = to_emr(ibmr);

	if (mr->mem.mtt_nents >= mr->mem.page_cnt)
		return -1;

	*((u64 *)mr->mem.mtt_buf + mr->mem.mtt_nents) = addr;
	mr->mem.mtt_nents++;

	return 0;
}

int erdma_map_mr_sg(struct ib_mr *ibmr, struct scatterlist *sg, int sg_nents,
		    unsigned int *sg_offset)
{
	struct erdma_mr *mr = to_emr(ibmr);
	int num;

	mr->mem.mtt_nents = 0;

	num = ib_sg_to_pages(&mr->ibmr, sg, sg_nents, sg_offset,
			     erdma_set_page);

	return num;
}

struct ib_mr *erdma_reg_user_mr(struct ib_pd *ibpd, u64 start, u64 len,
				u64 virt, int access, struct ib_udata *udata)
{
	struct erdma_dev *dev = to_edev(ibpd->device);
	struct erdma_mr *mr = NULL;
	u32 stag;
	int ret;
#ifdef HAVE_UDATA_TO_DRV_CONTEXT
	struct erdma_ucontext *uctx = rdma_udata_to_drv_context(
		udata, struct erdma_ucontext, ibucontext);
#else
	struct erdma_ucontext *uctx =
		ibpd->uobject ? to_ectx(ibpd->uobject->context) : NULL;
#endif

	ERDMA_INC_CNT(dev, CMD_REG_USR_MR);

	if (!len || len > dev->attrs.max_mr_size) {
		ibdev_err(&dev->ibdev,
			  "ERROR: Out of mr size: %llu, max %llu\n", len,
			  dev->attrs.max_mr_size);
		ERDMA_INC_CNT(dev, CMD_REG_USR_MR_FAILED);
		return ERR_PTR(-EINVAL);
	}

	mr = kzalloc(sizeof(*mr), GFP_KERNEL);
	if (!mr)
		return ERR_PTR(-ENOMEM);

	ret = get_mtt_entries(udata, uctx, &mr->mem, start, len, access, virt,
			      SZ_2G - SZ_4K, 0, true);
	if (ret)
		goto err_out_free;

	ret = erdma_create_stag(dev, &stag);
	if (ret)
		goto err_out_put_mtt;

	mr->ibmr.lkey = mr->ibmr.rkey = stag;
	mr->ibmr.pd = ibpd;
	mr->mem.va = virt;
	mr->mem.len = len;
	mr->access = ERDMA_MR_ACC_LR | to_erdma_access_flags(access);
	mr->valid = 1;
	mr->type = ERDMA_MR_TYPE_NORMAL;

	ret = regmr_cmd(dev, mr);
	if (ret) {
		ret = -EIO;
		goto err_out_mr;
	}

	return &mr->ibmr;

err_out_mr:
	erdma_free_idx(&dev->res_cb[ERDMA_RES_TYPE_STAG_IDX],
		       mr->ibmr.lkey >> 8);

err_out_put_mtt:
	put_mtt_entries(dev, &mr->mem);

err_out_free:
	kfree(mr);

	ERDMA_INC_CNT(dev, CMD_REG_USR_MR_FAILED);
	return ERR_PTR(ret);
}

#ifdef HAVE_DESTROY_QP_UDATA
int erdma_dereg_mr(struct ib_mr *ibmr, struct ib_udata *udata)
#else
int erdma_dereg_mr(struct ib_mr *ibmr)
#endif
{
	struct erdma_dev *dev = to_edev(ibmr->device);
	struct erdma_mr *mr = to_emr(ibmr);
	struct erdma_cmdq_dereg_mr_req req;
	int ret;

	ERDMA_INC_CNT(dev, CMD_DEREG_MR);

	erdma_cmdq_build_reqhdr(&req.hdr, CMDQ_SUBMOD_RDMA,
				CMDQ_OPCODE_DEREG_MR);

	req.cfg = FIELD_PREP(ERDMA_CMD_MR_MPT_IDX_MASK, ibmr->lkey >> 8) |
		  FIELD_PREP(ERDMA_CMD_MR_KEY_MASK, ibmr->lkey & 0xFF);

	ret = erdma_post_cmd_wait(&dev->cmdq, &req, sizeof(req), NULL, NULL);
	if (ret) {
		ERDMA_INC_CNT(dev, CMD_DEREG_MR_FAILED);
		dev_err(&dev->pdev->dev,
			"ERROR: err code = %d, cmd of dereg mr failed.\n", ret);
		return ret;
	}

	erdma_free_idx(&dev->res_cb[ERDMA_RES_TYPE_STAG_IDX], ibmr->lkey >> 8);

	put_mtt_entries(dev, &mr->mem);

	kfree(mr);
	return 0;
}

#ifdef HAVE_IB_VOID_DESTROY_CQ
void erdma_destroy_cq(struct ib_cq *ibcq, struct ib_udata *udata)
#elif defined(HAVE_IB_DEV_OPS)
int erdma_destroy_cq(struct ib_cq *ibcq, struct ib_udata *udata)
#else
int erdma_destroy_cq(struct ib_cq *ibcq)
#endif
{
	struct erdma_cq *cq = to_ecq(ibcq);
	struct erdma_dev *dev = to_edev(ibcq->device);
#ifdef HAVE_UDATA_TO_DRV_CONTEXT
	struct erdma_ucontext *ctx = rdma_udata_to_drv_context(
		udata, struct erdma_ucontext, ibucontext);
#else
	struct erdma_ucontext *ctx = cq->ucontext;
#endif
	int err;
	struct erdma_cmdq_destroy_cq_req req;

	ERDMA_INC_CNT(dev, CMD_DESTROY_CQ);

	hrtimer_cancel(&cq->dim.timer);

	erdma_cmdq_build_reqhdr(&req.hdr, CMDQ_SUBMOD_RDMA,
				CMDQ_OPCODE_DESTROY_CQ);
	req.cqn = cq->cqn;

	err = erdma_post_cmd_wait(&dev->cmdq, &req, sizeof(req), NULL, NULL);
	if (err) {
		dev_err(&dev->pdev->dev,
			"ERROR: err code = %d, cmd of destroy cq failed.\n",
			err);
		ERDMA_INC_CNT(dev, CMD_DESTROY_CQ_FAILED);
#ifndef HAVE_IB_VOID_DESTROY_CQ
		return err;
#endif
	}
#ifdef HAVE_RDMA_RESTRACK_ENTRY_USER
	if (rdma_is_kernel_res(&cq->ibcq.res)) {
#else
	if (!cq->user) {
#endif
		dma_free_coherent(&dev->pdev->dev,
				  WARPPED_BUFSIZE(cq->depth << CQE_SHIFT),
				  cq->kern_cq.qbuf, cq->kern_cq.qbuf_dma_addr);
	} else {
		erdma_unmap_user_dbrecords(ctx, &cq->user_cq.user_dbr_page);
		put_mtt_entries(dev, &cq->user_cq.qbuf_mtt);
	}

#ifdef HAVE_XARRAY
	xa_erase(&dev->cq_xa, cq->cqn);
#else
	idr_remove_safe(&dev->cq_idr, cq->cqn, &dev->idr_lock);
#endif
#ifndef HAVE_CQ_CORE_ALLOCATION
	kfree(cq);
#endif
#ifndef HAVE_IB_VOID_DESTROY_CQ
	return 0;
#endif
}

static void erdma_ib_lock_cqs(struct erdma_cq *send_cq,
			      struct erdma_cq *recv_cq)
	__acquires(&send_cq->kern_cq.lock) __acquires(&recv_cq->kern_cq.lock)
{
	if (send_cq) {
		if (recv_cq) {
			if (send_cq->cqn < recv_cq->cqn) {
				spin_lock(&send_cq->kern_cq.lock);
				spin_lock_nested(&recv_cq->kern_cq.lock,
						 SINGLE_DEPTH_NESTING);
			} else if (send_cq->cqn == recv_cq->cqn) {
				spin_lock(&send_cq->kern_cq.lock);
				__acquire(&recv_cq->kern_cq.lock);
			} else {
				spin_lock(&recv_cq->kern_cq.lock);
				spin_lock_nested(&send_cq->kern_cq.lock,
						 SINGLE_DEPTH_NESTING);
			}
		} else {
			spin_lock(&send_cq->kern_cq.lock);
			__acquire(&recv_cq->kern_cq.lock);
		}
	} else if (recv_cq) {
		spin_lock(&recv_cq->kern_cq.lock);
		__acquire(&send_cq->kern_cq.lock);
	} else {
		__acquire(&send_cq->kern_cq.lock);
		__acquire(&recv_cq->kern_cq.lock);
	}
}

static void erdma_ib_unlock_cqs(struct erdma_cq *send_cq,
				struct erdma_cq *recv_cq)
	__releases(&send_cq->kern_cq.lock) __releases(&recv_cq->kern_cq.lock)
{
	if (send_cq) {
		if (recv_cq) {
			if (send_cq->cqn < recv_cq->cqn) {
				spin_unlock(&recv_cq->kern_cq.lock);
				spin_unlock(&send_cq->kern_cq.lock);
			} else if (send_cq->cqn == recv_cq->cqn) {
				__release(&recv_cq->kern_cq.lock);
				spin_unlock(&send_cq->kern_cq.lock);
			} else {
				spin_unlock(&send_cq->kern_cq.lock);
				spin_unlock(&recv_cq->kern_cq.lock);
			}
		} else {
			__release(&recv_cq->kern_cq.lock);
			spin_unlock(&send_cq->kern_cq.lock);
		}
	} else if (recv_cq) {
		__release(&send_cq->kern_cq.lock);
		spin_unlock(&recv_cq->kern_cq.lock);
	} else {
		__release(&recv_cq->kern_cq.lock);
		__release(&send_cq->kern_cq.lock);
	}
}

#ifdef HAVE_DESTROY_QP_UDATA
int erdma_destroy_qp(struct ib_qp *ibqp, struct ib_udata *udata)
#else
int erdma_destroy_qp(struct ib_qp *ibqp)
#endif
{
	struct erdma_qp *qp = to_eqp(ibqp);
	struct erdma_dev *dev = to_edev(ibqp->device);
#ifdef HAVE_UDATA_TO_DRV_CONTEXT
	struct erdma_ucontext *ctx = rdma_udata_to_drv_context(
		udata, struct erdma_ucontext, ibucontext);
#else
	struct erdma_ucontext *ctx =
		ibqp->pd->uobject ? to_ectx(ibqp->pd->uobject->context) : NULL;
#endif
	struct erdma_qp_attrs qp_attrs;
	int err;
	struct erdma_cmdq_destroy_qp_req req;
	unsigned long flags;

	ERDMA_INC_CNT(dev, CMD_DESTROY_QP);

#ifdef HAVE_RDMA_RESTRACK_ENTRY_USER
	if (rdma_is_kernel_res(&qp->ibqp.res)) {
#else
	if (!qp->user) {
#endif
		local_irq_save(flags);
		erdma_ib_lock_cqs(qp->scq, qp->rcq);
		qp->attrs.flags |= ERDMA_QP_IN_DESTROY;
		erdma_ib_unlock_cqs(qp->scq, qp->rcq);
		local_irq_restore(flags);
	}

	down_write(&qp->state_lock);
	qp_attrs.state = ERDMA_QP_STATE_ERROR;
	erdma_modify_qp_internal(qp, &qp_attrs, ERDMA_QP_ATTR_STATE);
	up_write(&qp->state_lock);

	cancel_delayed_work_sync(&qp->reflush_dwork);

	erdma_cmdq_build_reqhdr(&req.hdr, CMDQ_SUBMOD_RDMA,
				CMDQ_OPCODE_DESTROY_QP);
	req.qpn = QP_ID(qp);

	err = erdma_post_cmd_wait(&dev->cmdq, &req, sizeof(req), NULL, NULL);
	if (err) {
		dev_err(&dev->pdev->dev,
			"ERROR: err code = %d, cmd of destroy qp failed.\n",
			err);
		ERDMA_INC_CNT(dev, CMD_DESTROY_QP_FAILED);
		return err;
	}

	erdma_qp_put(qp);
	wait_for_completion(&qp->safe_free);

#ifdef HAVE_RDMA_RESTRACK_ENTRY_USER
	if (rdma_is_kernel_res(&qp->ibqp.res)) {
#else
	if (!qp->user) {
#endif
		free_kernel_qp(qp);
	} else {
		put_mtt_entries(dev, &qp->user_qp.sq_mtt);
		put_mtt_entries(dev, &qp->user_qp.rq_mtt);
		erdma_unmap_user_dbrecords(ctx, &qp->user_qp.user_dbr_page);
	}

	if (qp->cep)
		erdma_cep_put(qp->cep);

#ifdef HAVE_XARRAY
	xa_erase(&dev->qp_xa, QP_ID(qp));
#else
	idr_remove_safe(&dev->qp_idr, QP_ID(qp), &dev->idr_lock);
#endif

#ifndef HAVE_QP_CORE_ALLOCATION
	kfree(qp);
#endif
	return 0;
}

void erdma_qp_get_ref(struct ib_qp *ibqp)
{
	erdma_qp_get(to_eqp(ibqp));
}

void erdma_qp_put_ref(struct ib_qp *ibqp)
{
	erdma_qp_put(to_eqp(ibqp));
}

int erdma_mmap(struct ib_ucontext *ctx, struct vm_area_struct *vma)
{
	struct rdma_user_mmap_entry *rdma_entry;
	struct erdma_user_mmap_entry *entry;
	pgprot_t prot;
	int err = -EINVAL;

	rdma_entry = rdma_user_mmap_entry_get(ctx, vma);
	if (!rdma_entry)
		return -EINVAL;

	entry = to_emmap(rdma_entry);

	switch (entry->mmap_flag) {
	case ERDMA_MMAP_IO_NC:
		/* map doorbell. */
		prot = pgprot_noncached(vma->vm_page_prot);
#ifdef HAVE_CORE_MMAP_XA
		err = rdma_user_mmap_io(ctx, vma, PFN_DOWN(entry->address),
					PAGE_SIZE, prot, rdma_entry);
#elif defined(HAVE_RDMA_USER_MMAP_IO)
		err = rdma_user_mmap_io(ctx, vma, PFN_DOWN(entry->address),
					PAGE_SIZE, prot);
#else
		vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
		err = io_remap_pfn_range(vma, vma->vm_start,
					 PFN_DOWN(entry->address), PAGE_SIZE,
					 prot);
#endif
		break;
	default:
		return -EINVAL;
	}

	rdma_user_mmap_entry_put(rdma_entry);
	return err;
}

#ifdef HAVE_CORE_MMAP_XA
void erdma_mmap_free(struct rdma_user_mmap_entry *rdma_entry)
{
	struct erdma_user_mmap_entry *entry = to_emmap(rdma_entry);

	kfree(entry);
}
#endif

#define ERDMA_SDB_PAGE 0
#define ERDMA_SDB_ENTRY 1
#define ERDMA_SDB_SHARED 2

static void alloc_db_resources(struct erdma_dev *dev,
			       struct erdma_ucontext *ctx)
{
	struct erdma_devattr *attrs = &dev->attrs;
	u32 bitmap_idx, hw_page_idx;

	if (attrs->disable_dwqe)
		goto alloc_normal_db;

	/* Try to alloc independent SDB page. */
	spin_lock(&dev->db_bitmap_lock);
	bitmap_idx = find_first_zero_bit(dev->sdb_page, attrs->dwqe_pages);
	if (bitmap_idx != attrs->dwqe_pages) {
		set_bit(bitmap_idx, dev->sdb_page);
		spin_unlock(&dev->db_bitmap_lock);

		ctx->sdb_type = ERDMA_SDB_PAGE;
		ctx->sdb_bitmap_idx = bitmap_idx;
		ctx->sdb = dev->func_bar_addr + ERDMA_BAR_SQDB_SPACE_OFFSET +
			   (bitmap_idx << ERDMA_HW_PAGE_SHIFT);

		return;
	}

	bitmap_idx = find_first_zero_bit(dev->sdb_entry, attrs->dwqe_entries);
	if (bitmap_idx != attrs->dwqe_entries) {
		set_bit(bitmap_idx, dev->sdb_entry);
		spin_unlock(&dev->db_bitmap_lock);

		ctx->sdb_type = ERDMA_SDB_ENTRY;
		ctx->sdb_bitmap_idx = bitmap_idx;
		hw_page_idx = attrs->dwqe_pages +
			      bitmap_idx / ERDMA_DWQE_TYPE1_CNT_PER_PAGE;
		ctx->sdb_entid = bitmap_idx % ERDMA_DWQE_TYPE1_CNT_PER_PAGE;
		ctx->sdb = dev->func_bar_addr + ERDMA_BAR_SQDB_SPACE_OFFSET +
			   (hw_page_idx << ERDMA_HW_PAGE_SHIFT);

		return;
	}

	spin_unlock(&dev->db_bitmap_lock);

alloc_normal_db:
	ctx->sdb_type = ERDMA_SDB_SHARED;
	ctx->sdb = dev->func_bar_addr +
		   (ERDMA_SDB_SHARED_PAGE_INDEX << ERDMA_HW_PAGE_SHIFT);
}

static void erdma_uctx_user_mmap_entries_remove(struct erdma_ucontext *uctx)
{
	rdma_user_mmap_entry_remove(uctx->sq_db_mmap_entry);
	rdma_user_mmap_entry_remove(uctx->rq_db_mmap_entry);
	rdma_user_mmap_entry_remove(uctx->cq_db_mmap_entry);
}

int erdma_alloc_ucontext(struct ib_ucontext *ibctx, struct ib_udata *udata)
{
	struct erdma_dev *dev = to_edev(ibctx->device);
	struct erdma_ucontext *ctx = to_ectx(ibctx);
	struct erdma_uresp_alloc_ctx uresp = {};
	int ret;

	ERDMA_INC_CNT(dev, CMD_ALLOC_UCTX);

	if (atomic_inc_return(&dev->num_ctx) > ERDMA_MAX_CONTEXT) {
		ret = -ENOMEM;
		goto err_out;
	}

	INIT_LIST_HEAD(&ctx->dbrecords_page_list);
	mutex_init(&ctx->dbrecords_page_mutex);

#ifndef HAVE_CORE_MMAP_XA
	mutex_init(&ctx->lock);
	INIT_LIST_HEAD(&ctx->pending_mmaps);
#endif

	alloc_db_resources(dev, ctx);

	ctx->rdb = dev->func_bar_addr + ERDMA_BAR_RQDB_SPACE_OFFSET;
	ctx->cdb = dev->func_bar_addr + ERDMA_BAR_CQDB_SPACE_OFFSET;

	ctx->sq_db_mmap_entry = erdma_user_mmap_entry_insert(
		ibctx, (u64)ctx->sdb, PAGE_SIZE, ERDMA_MMAP_IO_NC, &uresp.sdb);
	if (!ctx->sq_db_mmap_entry) {
		ret = -ENOMEM;
		goto err_out;
	}

	ctx->rq_db_mmap_entry = erdma_user_mmap_entry_insert(
		ibctx, (u64)ctx->rdb, PAGE_SIZE, ERDMA_MMAP_IO_NC, &uresp.rdb);
	if (!ctx->sq_db_mmap_entry) {
		ret = -EINVAL;
		goto err_out;
	}

	ctx->cq_db_mmap_entry = erdma_user_mmap_entry_insert(
		ibctx, (u64)ctx->cdb, PAGE_SIZE, ERDMA_MMAP_IO_NC, &uresp.cdb);
	if (!ctx->cq_db_mmap_entry) {
		ret = -EINVAL;
		goto err_out;
	}

	uresp.dev_id = dev->pdev->device;
	uresp.sdb_type = ctx->sdb_type;
	uresp.sdb_entid = ctx->sdb_entid;
	uresp.sdb_off = ctx->sdb & ~PAGE_MASK;
	uresp.rdb_off = ctx->rdb & ~PAGE_MASK;
	uresp.cdb_off = ctx->cdb & ~PAGE_MASK;

	ret = ib_copy_to_udata(udata, &uresp,
			       min(sizeof(uresp), udata->outlen));
	if (ret)
		goto err_out;

	return 0;

err_out:
	erdma_uctx_user_mmap_entries_remove(ctx);
	atomic_dec(&dev->num_ctx);

	if (ret)
		ERDMA_INC_CNT(dev, CMD_ALLOC_UCTX_FAILED);

	return ret;
}

#ifndef HAVE_UCONTEXT_CORE_ALLOCATION
struct ib_ucontext *erdma_kzalloc_ucontext(struct ib_device *ibdev,
					   struct ib_udata *udata)
{
	struct erdma_ucontext *ctx = NULL;
	int ret;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx) {
		ret = -ENOMEM;
		goto out;
	}

	ctx->ibucontext.device = ibdev;

	ret = erdma_alloc_ucontext(&ctx->ibucontext, udata);
	if (ret)
		goto out_free;

	return &ctx->ibucontext;

out_free:
	kfree(ctx);
out:
	return ERR_PTR(ret);
}
#endif

#ifdef HAVE_UCONTEXT_CORE_ALLOCATION
void erdma_dealloc_ucontext(struct ib_ucontext *ibctx)
#else
int erdma_dealloc_ucontext(struct ib_ucontext *ibctx)
#endif
{
	struct erdma_ucontext *ctx = to_ectx(ibctx);
	struct erdma_dev *dev = to_edev(ibctx->device);

	ERDMA_INC_CNT(dev, CMD_DEALLOC_UCTX);

	spin_lock(&dev->db_bitmap_lock);
	if (ctx->sdb_type == ERDMA_SDB_PAGE)
		clear_bit(ctx->sdb_bitmap_idx, dev->sdb_page);
	else if (ctx->sdb_type == ERDMA_SDB_ENTRY)
		clear_bit(ctx->sdb_bitmap_idx, dev->sdb_entry);
#ifndef HAVE_CORE_MMAP_XA
	mmap_entries_remove_free(dev, ctx);
#endif
	erdma_uctx_user_mmap_entries_remove(ctx);

	spin_unlock(&dev->db_bitmap_lock);

	atomic_dec(&dev->num_ctx);
#ifndef HAVE_UCONTEXT_CORE_ALLOCATION
	kfree(ctx);
	return 0;
#endif
}

static int ib_qp_state_to_erdma_qp_state[IB_QPS_ERR + 1] = {
	[IB_QPS_RESET] = ERDMA_QP_STATE_IDLE,
	[IB_QPS_INIT] = ERDMA_QP_STATE_IDLE,
	[IB_QPS_RTR] = ERDMA_QP_STATE_RTR,
	[IB_QPS_RTS] = ERDMA_QP_STATE_RTS,
	[IB_QPS_SQD] = ERDMA_QP_STATE_CLOSING,
	[IB_QPS_SQE] = ERDMA_QP_STATE_TERMINATE,
	[IB_QPS_ERR] = ERDMA_QP_STATE_ERROR
};

static int erdma_av_from_attr(struct erdma_qp *qp, struct ib_qp_attr *attr)
{
#ifdef HAVE_CREATE_AH_RDMA_ATTR
	struct rdma_ah_attr *ah_attr = &attr->ah_attr;
#ifdef HAVE_IB_GLOBAL_ROUTE_WITH_SGID_ATTR
	const struct ib_gid_attr *sgid_attr = ah_attr->grh.sgid_attr;
#else
	struct ib_gid_attr sgid_attr;
	int err;
#endif
	enum rdma_network_type ntype;
	union ib_gid sgid;

	if (ah_attr->type != RDMA_AH_ATTR_TYPE_ROCE) {
		dprint(DBG_QP, "unsupport ah_attr type %u.\n", ah_attr->type);
		return -ENOTSUPP;
	}

#ifdef HAVE_IB_GLOBAL_ROUTE_WITH_SGID_ATTR
	ntype = rdma_gid_attr_network_type(sgid_attr);
	sgid = sgid_attr->gid;
#else
	err = ib_get_cached_gid(&qp->dev->ibdev, rdma_ah_get_port_num(ah_attr),
				rdma_ah_read_grh(ah_attr)->sgid_index, &sgid,
				&sgid_attr);
	if (err)
		return err;

	ntype = ib_gid_to_network_type(sgid_attr.gid_type, &sgid);

	if (sgid_attr.ndev)
		dev_put(sgid_attr.ndev);
#endif

	dprint(DBG_QP, "gid type:%u, sgid: %pI6\n", ntype, sgid.raw);

	rdma_gid2ip((struct sockaddr *)&qp->attrs.laddr, &sgid);
	rdma_gid2ip((struct sockaddr *)&qp->attrs.raddr,
		    &rdma_ah_read_grh(ah_attr)->dgid);

	dprint(DBG_QP, "dgid: %pI6\n", rdma_ah_read_grh(ah_attr)->dgid.raw);

	dprint(DBG_QP, "laddr:0x%x\n",
	       ntohl(qp->attrs.laddr.in.sin_addr.s_addr));
	dprint(DBG_QP, "raddr:0x%x\n",
	       ntohl(qp->attrs.raddr.in.sin_addr.s_addr));
#endif
	return 0;
}

static int erdma_handle_compat_attr(struct erdma_qp *qp,
				    struct ib_qp_attr *attr, int attr_mask)
{
	dprint(DBG_QP, "attr mask: %x, av: %d, state:%d\n", attr_mask,
	       attr_mask & IB_QP_AV, attr_mask & IB_QP_STATE);

	if (attr_mask & IB_QP_AV)
		erdma_av_from_attr(qp, attr);

	if (attr_mask & IB_QP_DEST_QPN) {
		dprint(DBG_QP, "get remote qpn %u\n", attr->dest_qp_num);
		qp->attrs.remote_qp_num = attr->dest_qp_num;
	}

	if (attr_mask & IB_QP_SQ_PSN) {
		dprint(DBG_QP, "get sqsn:%u\n", attr->sq_psn);
		qp->attrs.sq_psn = attr->sq_psn;
	}

	if (attr_mask & IB_QP_RQ_PSN) {
		dprint(DBG_QP, "get rqsn:%u\n", attr->rq_psn);
		qp->attrs.rq_psn = attr->rq_psn;
	}

	return 0;
}

#define IB_QP_OOB_CONN_ATTR IB_QP_RESERVED1
int erdma_modify_qp(struct ib_qp *ibqp, struct ib_qp_attr *attr, int attr_mask,
		    struct ib_udata *udata)
{
	enum erdma_qp_attr_mask erdma_attr_mask = 0;
	struct erdma_qp *qp = to_eqp(ibqp);
	struct erdma_qp_attrs new_attrs;
	int ret = 0;

#ifdef HAVE_UVERBS_CMD_MASK_NOT_NEEDED
	if (attr_mask & ~IB_QP_ATTR_STANDARD_BITS)
		return -EOPNOTSUPP;
#endif

	if (attr_mask & IB_QP_OOB_CONN_ATTR) {
		ret = update_kernel_qp_oob_attr(qp);
		if (ret)
			return ret;
	}

	if (compat_mode)
		erdma_handle_compat_attr(qp, attr, attr_mask);

	memset(&new_attrs, 0, sizeof(new_attrs));

	if (attr_mask & IB_QP_STATE) {
		new_attrs.state = ib_qp_state_to_erdma_qp_state[attr->qp_state];
		if ((qp->attrs.connect_without_cm || compat_mode) &&
		    new_attrs.state == ERDMA_QP_STATE_RTR)
			new_attrs.state = ERDMA_QP_STATE_RTS;
		erdma_attr_mask |= ERDMA_QP_ATTR_STATE;
	}

	down_write(&qp->state_lock);

	ret = erdma_modify_qp_internal(qp, &new_attrs, erdma_attr_mask);

	up_write(&qp->state_lock);

	return ret;
}

static inline enum ib_qp_state query_qp_state(struct erdma_qp *qp)
{
	switch (qp->attrs.state) {
	case ERDMA_QP_STATE_IDLE:
		return IB_QPS_INIT;
	case ERDMA_QP_STATE_RTR:
		return IB_QPS_RTR;
	case ERDMA_QP_STATE_RTS:
		return IB_QPS_RTS;
	case ERDMA_QP_STATE_CLOSING:
		return IB_QPS_ERR;
	case ERDMA_QP_STATE_TERMINATE:
		return IB_QPS_ERR;
	case ERDMA_QP_STATE_ERROR:
		return IB_QPS_ERR;
	default:
		return IB_QPS_ERR;
	}
}

int erdma_query_qp(struct ib_qp *ibqp, struct ib_qp_attr *qp_attr,
		   int qp_attr_mask, struct ib_qp_init_attr *qp_init_attr)
{
	struct erdma_qp *qp;
	struct erdma_dev *dev;

	if (ibqp && qp_attr && qp_init_attr) {
		qp = to_eqp(ibqp);
		dev = to_edev(ibqp->device);
	} else {
		return -EINVAL;
	}

	qp_attr->cap.max_inline_data = ERDMA_MAX_INLINE;
	qp_init_attr->cap.max_inline_data = ERDMA_MAX_INLINE;

	qp_attr->cap.max_send_wr = qp->attrs.sq_size;
	qp_attr->cap.max_recv_wr = qp->attrs.rq_size;
	qp_attr->cap.max_send_sge = qp->attrs.max_send_sge;
	qp_attr->cap.max_recv_sge = qp->attrs.max_recv_sge;

	qp_attr->path_mtu = ib_mtu_int_to_enum(dev->netdev->mtu);
	qp_attr->max_rd_atomic = qp->attrs.irq_size;
	qp_attr->max_dest_rd_atomic = qp->attrs.orq_size;

	qp_attr->qp_access_flags = IB_ACCESS_LOCAL_WRITE |
				   IB_ACCESS_REMOTE_WRITE |
				   IB_ACCESS_REMOTE_READ;

	qp_init_attr->cap = qp_attr->cap;

	qp_attr->qp_state = query_qp_state(qp);
	qp_attr->cur_qp_state = query_qp_state(qp);

	return 0;
}

static int erdma_init_user_cq(struct ib_udata *udata,
			      struct erdma_ucontext *uctx, struct erdma_cq *cq,
			      struct erdma_ureq_create_cq *ureq)
{
	struct erdma_dev *dev = to_edev(cq->ibcq.device);
	int ret;

	ret = get_mtt_entries(udata, uctx, &cq->user_cq.qbuf_mtt, ureq->qbuf_va,
			      ureq->qbuf_len, 0, ureq->qbuf_va, SZ_64M - SZ_4K,
			      1, false);
	if (ret)
		return ret;

	ret = erdma_map_user_dbrecords(udata, uctx, ureq->db_record_va,
				       &cq->user_cq.user_dbr_page,
				       &cq->user_cq.db_info_dma_addr);
	if (ret)
		put_mtt_entries(dev, &cq->user_cq.qbuf_mtt);

	return ret;
}

static int erdma_init_kernel_cq(struct erdma_cq *cq)
{
	struct erdma_dev *dev = to_edev(cq->ibcq.device);

	cq->kern_cq.qbuf =
		dma_alloc_coherent(&dev->pdev->dev,
				   WARPPED_BUFSIZE(cq->depth << CQE_SHIFT),
				   &cq->kern_cq.qbuf_dma_addr, GFP_KERNEL);
	if (!cq->kern_cq.qbuf)
		return -ENOMEM;

	cq->kern_cq.db_record =
		(u64 *)(cq->kern_cq.qbuf + (cq->depth << CQE_SHIFT));
	spin_lock_init(&cq->kern_cq.lock);
	/* use default cqdb addr */
	cq->kern_cq.db = dev->func_bar + ERDMA_BAR_CQDB_SPACE_OFFSET;

	return 0;
}

int erdma_create_cq(struct ib_cq *ibcq, const struct ib_cq_init_attr *attr,
		    struct ib_udata *udata)
{
	struct erdma_dev *dev = to_edev(ibcq->device);
	struct erdma_cq *cq = to_ecq(ibcq);
	unsigned int depth = attr->cqe;
	int ret;
#ifdef HAVE_UDATA_TO_DRV_CONTEXT
	struct erdma_ucontext *uctx = rdma_udata_to_drv_context(
		udata, struct erdma_ucontext, ibucontext);
#else
	struct erdma_ucontext *uctx = cq->ucontext;
#endif

	ERDMA_INC_CNT(dev, CMD_CREATE_CQ);

	if (depth > dev->attrs.max_cqe) {
		dev_warn(&dev->pdev->dev,
			 "WARN: exceed cqe(%d) > capbility(%d)\n", depth,
			 dev->attrs.max_cqe);
		ERDMA_INC_CNT(dev, CMD_CREATE_CQ_FAILED);
		return -EINVAL;
	}

	depth = roundup_pow_of_two(depth);
	cq->ibcq.cqe = depth;
	cq->depth = depth;
	cq->assoc_eqn = attr->comp_vector + 1;

#ifdef HAVE_XARRAY
	ret = xa_alloc_cyclic(&dev->cq_xa, &cq->cqn, cq,
			      XA_LIMIT(1, dev->attrs.max_cq - 1),
			      &dev->next_alloc_cqn, GFP_KERNEL);
#else
	ret = idr_alloc_cyclic_safe(&dev->cq_idr, &cq->cqn, cq, &dev->idr_lock,
				    &dev->next_alloc_cqn, dev->attrs.max_cq);
#endif
	if (ret < 0) {
		ERDMA_INC_CNT(dev, CMD_CREATE_CQ_FAILED);
		return ret;
	}

	if (udata) {
		struct erdma_ureq_create_cq ureq;
		struct erdma_uresp_create_cq uresp;

		ret = ib_copy_from_udata(&ureq, udata,
					 min(udata->inlen, sizeof(ureq)));
		if (ret)
			goto err_out_xa;

		ret = erdma_init_user_cq(udata, uctx, cq, &ureq);
		if (ret)
			goto err_out_xa;

		uresp.cq_id = cq->cqn;
		uresp.num_cqe = depth;

		ret = ib_copy_to_udata(udata, &uresp,
				       min(sizeof(uresp), udata->outlen));
		if (ret)
			goto err_free_res;
	} else {
		ret = erdma_init_kernel_cq(cq);
		if (ret)
			goto err_out_xa;
	}

	ret = create_cq_cmd(dev, cq, udata ? true : false);
	if (ret)
		goto err_free_res;

	hrtimer_init(&cq->dim.timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	cq->dim.timer.function = cq_timer_fn;

	return 0;

err_free_res:
	if (udata) {
		erdma_unmap_user_dbrecords(uctx, &cq->user_cq.user_dbr_page);
		put_mtt_entries(dev, &cq->user_cq.qbuf_mtt);
	} else {
		dma_free_coherent(&dev->pdev->dev,
				  WARPPED_BUFSIZE(depth << CQE_SHIFT),
				  cq->kern_cq.qbuf, cq->kern_cq.qbuf_dma_addr);
	}

err_out_xa:
#ifdef HAVE_XARRAY
	xa_erase(&dev->cq_xa, cq->cqn);
#else
	idr_remove_safe(&dev->cq_idr, cq->cqn, &dev->idr_lock);
#endif
	ERDMA_INC_CNT(dev, CMD_CREATE_CQ_FAILED);
	return ret;
}

#ifndef HAVE_CQ_CORE_ALLOCATION
struct ib_cq *erdma_kzalloc_cq(struct ib_device *ibdev,
			       const struct ib_cq_init_attr *attr,
			       struct ib_ucontext *ib_context,
			       struct ib_udata *udata)
{
	struct erdma_cq *cq = NULL;
	struct erdma_dev *edev;
	int ret;
	bool user_access = (udata != NULL) ? true : false;

	if (!ibdev) {
		pr_err("ERROR: NO OFA device\n");
		ret = -ENODEV;
		goto err_out;
	}
	edev = to_edev(ibdev);

	if (user_access && !ib_context) {
		dev_err(&edev->pdev->dev, "ERROR: invalid ib_context.\n");
		ret = -EINVAL;
		goto err_out;
	}

	cq = kzalloc(sizeof(*cq), GFP_KERNEL);
	if (!cq) {
		ret = -ENOMEM;
		goto err_out;
	}

#ifdef HAVE_UDATA_TO_DRV_CONTEXT
	cq->ucontext = rdma_udata_to_drv_context(udata, struct erdma_ucontext,
						 ibucontext);
#else
	cq->ucontext = to_ectx(ib_context);
#endif

#ifdef HAVE_RDMA_RESTRACK_ENTRY_USER
	cq->ibcq.res.user = udata ? 1 : 0;
#else
#ifdef HAVE_IB_CQ_WITH_RES
	cq->ibcq.res.task = udata ? current : NULL;
#endif
	cq->user = udata ? 1 : 0;
#endif

	cq->ibcq.device = ibdev;
	ret = erdma_create_cq(&cq->ibcq, attr, udata);
	if (ret)
		goto err_free_cq;

#ifdef HAVE_IB_CQ_WITH_RES
	cq->ibcq.res.task = NULL;
#endif
	return &cq->ibcq;

err_free_cq:
	kfree(cq);
err_out:
	return ERR_PTR(ret);
}
#endif

struct net_device *erdma_get_netdev(struct ib_device *device, port_t port_num)
{
	struct erdma_dev *edev = to_edev(device);

	if (edev->netdev)
		dev_hold(edev->netdev);

	return edev->netdev;
}

void erdma_disassociate_ucontext(struct ib_ucontext *ibcontext)
{
}

void erdma_set_mtu(struct erdma_dev *dev, u32 mtu)
{
	struct erdma_cmdq_config_mtu_req req;

	erdma_cmdq_build_reqhdr(&req.hdr, CMDQ_SUBMOD_COMMON,
				CMDQ_OPCODE_CONF_MTU);
	req.mtu = mtu;

	erdma_post_cmd_wait(&dev->cmdq, &req, sizeof(req), NULL, NULL);
}

int erdma_set_retrans_num(struct erdma_dev *dev, u32 retrans_num)
{
	struct erdma_cmdq_set_retrans_num_req req;
	int ret;

	if (retrans_num == 0 || retrans_num > 0xffUL)
		return -EINVAL;

	erdma_cmdq_build_reqhdr(&req.hdr, CMDQ_SUBMOD_COMMON,
				CMDQ_OPCODE_SET_RETRANS_NUM);
	req.retrans_num = retrans_num;

	ret = erdma_post_cmd_wait(&dev->cmdq, &req, sizeof(req), NULL, NULL);
	if (!ret)
		dev->attrs.retrans_num = retrans_num;

	return ret;
}

void erdma_port_event(struct erdma_dev *dev, enum ib_event_type reason)
{
	struct ib_event event;

	event.device = &dev->ibdev;
	event.element.port_num = 1;
	event.event = reason;

	ib_dispatch_event(&event);
}

#ifndef HAVE_AH_CORE_ALLOCATION
#ifdef HAVE_CREATE_DESTROY_AH_FLAGS
struct ib_ah *erdma_kzalloc_ah(struct ib_pd *ibpd, struct rdma_ah_attr *ah_attr,
			       u32 flags, struct ib_udata *udata)
#elif defined(HAVE_CREATE_AH_RDMA_ATTR)
struct ib_ah *erdma_kzalloc_ah(struct ib_pd *ibpd, struct rdma_ah_attr *ah_attr,
			       struct ib_udata *udata)
#else
struct ib_ah *erdma_kzalloc_ah(struct ib_pd *ibpd, struct ib_ah_attr *ah_attr)
#endif
{
	return ERR_PTR(-EOPNOTSUPP);
}
#endif

#ifdef HAVE_AH_CORE_ALLOCATION_DESTROY_RC
int erdma_destroy_ah(struct ib_ah *ibah, u32 flags)
#elif defined(HAVE_AH_CORE_ALLOCATION)
void erdma_destroy_ah(struct ib_ah *ibah, u32 flags)
#elif defined(HAVE_CREATE_DESTROY_AH_FLAGS)
int erdma_destroy_ah(struct ib_ah *ibah, u32 flags)
#else
int erdma_destroy_ah(struct ib_ah *ibah)
#endif
{
#if defined(HAVE_AH_CORE_ALLOCATION) &&                                        \
	!defined(HAVE_AH_CORE_ALLOCATION_DESTROY_RC)
	return;
#else
	return -EOPNOTSUPP;
#endif
}

int erdma_query_hw_stats(struct erdma_dev *dev)
{
	struct erdma_cmdq_query_stats_resp *stats;
	struct erdma_cmdq_query_req req;
	dma_addr_t dma_addr;
	int err;

	erdma_cmdq_build_reqhdr(&req.hdr, CMDQ_SUBMOD_COMMON,
				CMDQ_OPCODE_GET_STATS);

	stats = dma_pool_alloc(dev->resp_pool, GFP_KERNEL, &dma_addr);
	if (!stats)
		return -ENOMEM;

	req.target_addr = dma_addr;
	req.target_length = ERDMA_HW_RESP_SIZE;
	/* Clear the magic fileds. */
	stats->hdr.magic = 0;

	err = erdma_post_cmd_wait(&dev->cmdq, &req, sizeof(req), NULL, NULL);
	if (err)
		goto out;

	if (stats->hdr.magic != 0x5566) {
		err = -EINVAL;
		goto out;
	}

	memcpy(&dev->stats.value[ERDMA_STATS_TX_REQS_CNT], &stats->tx_req_cnt,
	       sizeof(__u64) * (ERDMA_STATS_RX_PPS_METER_DROP_CNT -
				ERDMA_STATS_TX_REQS_CNT + 1));

out:
	dma_pool_free(dev->resp_pool, stats, dma_addr);

	return err;
}
