// SPDX-License-Identifier: GPL-2.0

/* Authors: Cheng Xu <chengyou@linux.alibaba.com> */
/*          Kai Shen <kaishen@linux.alibaba.com> */
/* Copyright (c) 2020-2025, Alibaba Group. */

#include "kcompat.h"

#ifdef HAVE_UAPI_DEF_SUPPORT
#include <rdma/ib_addr.h>
#include <rdma/ib_umem.h>
#ifdef HAVE_UDATA_TO_DRV_CONTEXT
#include <rdma/uverbs_ioctl.h>
#endif
#include <rdma/uverbs_std_types.h>

#include "erdma.h"
#include "erdma-abi.h"
#include "erdma_hw.h"
#include "erdma_verbs.h"
#include "erdma_devx.h"

#define UVERBS_MODULE_NAME erdma
#include <rdma/uverbs_named_ioctl.h>

static int
UVERBS_HANDLER(ERDMA_METHOD_DEVX_OTHER)(struct uverbs_attr_bundle *attrs)
{
	return -ENOTSUPP;
}

DECLARE_UVERBS_NAMED_METHOD(ERDMA_METHOD_DEVX_OTHER,
			    UVERBS_ATTR_PTR_IN(ERDMA_ATTR_DEVX_OTHER_CMD_IN,
					       UVERBS_ATTR_MIN_SIZE(128),
					       UA_MANDATORY, UA_ALLOC_AND_COPY),
			    UVERBS_ATTR_PTR_OUT(ERDMA_ATTR_DEVX_OTHER_CMD_OUT,
						UVERBS_ATTR_MIN_SIZE(32),
						UA_MANDATORY));

DECLARE_UVERBS_GLOBAL_METHODS(ERDMA_OBJECT_DEVX,
			      &UVERBS_METHOD(ERDMA_METHOD_DEVX_OTHER));

struct devx_umem {
	struct erdma_dev *dev;
	struct ib_umem *umem;
	u32 umem_id;
	u8 access;
	struct erdma_mtt *mtt;
	u32 page_offset;
	unsigned long page_size;
	size_t npages;
};

enum devx_obj_flags {
	DEVX_OBJ_FLAGS_RVSD0 = 1 << 0,
	DEVX_OBJ_FLAGS_RSVD1 = 1 << 1,
	DEVX_OBJ_FLAGS_CQ = 1 << 2,
	DEVX_OBJ_FLAGS_QP = 1 << 3,
};

struct devx_obj {
	struct erdma_dev *dev;
	struct devx_umem *devx_umem;
	u32 obj_id;
	u32 flags;

	union {
		struct erdma_cq cq;
		struct erdma_qp qp;
	};
};

static struct erdma_mtt *devx_create_sub_mtt(struct devx_umem *devx_umem,
					     u32 start_page_idx, u32 npages)
{
	dma_addr_t *tgt_page_list, *src_page_list;
	struct erdma_mtt *mtt, *tmp_mtt;
	u32 i;

	/* For QP/CQ buffer, we use a continuous MTT. */
	mtt = erdma_create_mtt(devx_umem->dev, MTT_SIZE(npages), true);
	if (IS_ERR(mtt))
		return mtt;

	/* Get the target page list */
	tgt_page_list = mtt->buf;

	/* Get the source page list */
	tmp_mtt = devx_umem->mtt;
	while (tmp_mtt->low_level)
		tmp_mtt = tmp_mtt->low_level;
	src_page_list = tmp_mtt->buf;

	/* Copy page list from src to target. */
	for (i = 0; i < npages; i++)
		tgt_page_list[i] = src_page_list[start_page_idx + i];

	return mtt;
}

static int devx_get_sub_mem(struct devx_umem *devx_umem, u32 off, u32 len,
			    struct erdma_mem *mem)
{
	u32 page_offset, npages, start_page_idx;
	struct erdma_mtt *mtt;

	page_offset = (off + devx_umem->page_offset) & (devx_umem->page_size - 1);
	npages = (len + page_offset + devx_umem->page_size - 1) / devx_umem->page_size;
	start_page_idx = (off + devx_umem->page_offset) / devx_umem->page_size;

	mtt = devx_create_sub_mtt(devx_umem, start_page_idx, npages);
	if (IS_ERR(mtt))
		return PTR_ERR(mtt);

	mem->type = ERDMA_UMEM_DEVX;
	mem->devx_umem = devx_umem;
	mem->page_size = devx_umem->page_size;
	mem->page_offset = page_offset;
	mem->page_cnt = npages;
	mem->mtt_nents = npages;
	mem->mtt = mtt;
	mem->offset = off;
	mem->len = len;

	return 0;
}

static void devx_put_sub_mem(struct erdma_mem *mem)
{
	erdma_destroy_mtt(((struct devx_umem *)(mem->devx_umem))->dev, mem->mtt);
}

static inline struct devx_umem *find_umem_by_id(struct erdma_dev *dev, int id)
{
#ifdef HAVE_XARRAY_API
	return (struct devx_umem *)xa_load(&dev->umem_xa, id);
#else
	return (struct devx_umem *)idr_find(&dev->umem_idr, id);
#endif
}

static int devx_destroy_cq(struct devx_obj *obj)
{
	struct erdma_cmdq_destroy_cq_req req;
	struct erdma_dev *dev = obj->dev;
	int err;

	erdma_cmdq_build_reqhdr(&req.hdr, CMDQ_SUBMOD_RDMA,
				CMDQ_OPCODE_DESTROY_CQ);
	req.cqn = obj->obj_id;

	err = erdma_post_cmd_wait(&dev->cmdq, &req, sizeof(req), NULL, NULL);
	if (err)
		return err;

	erdma_stats_sub_mtt_nents(dev, obj->cq.user_cq.qbuf_mtt.mtt_nents,
				  ERDMA_CQ_MTT_INLINE_THRESH);
	devx_put_sub_mem(&obj->cq.user_cq.qbuf_mtt);
	ERDMA_FREE_RES_ID(dev, cq, obj->obj_id);

	return 0;
}

static void devx_cq_event(struct erdma_cq *cq, enum ib_event_type event_type)
{
	pr_debug("devx_cq_event: cq %p, event_type %u.\n", cq, event_type);
}

static struct devx_obj *
devx_create_cq(struct erdma_dev *dev,
	       struct erdma_devx_create_object_cq_req *ureq)
{
	struct erdma_cmdq_create_cq_req req;
	struct devx_umem *umem, *dbrec_umem;
	struct erdma_mem *cq_mem;
	struct devx_obj *obj;
	u64 dbrec_dma;
	int err;

	pr_debug(
		"devx_create_cq:umem_handle:%u, depth:%u, eqn:%u, qbuf_len:%u, qbuf_offset:%u, dbrec_umem:%u, dbrec_offset:%u\n",
		ureq->umem_id, ureq->depth, ureq->eqn, ureq->max_qbuf_len,
		ureq->qbuf_offset, ureq->dbrec_umem_id, ureq->dbrec_offset);
	if (ureq->depth > dev->attrs.max_cqe || !is_power_of_2(ureq->depth)) {
		err = -EINVAL;
		goto error_out;
	}

	umem = find_umem_by_id(dev, ureq->umem_id);
	if (!umem) {
		err = -ENOSPC;
		goto error_out;
	}

	dbrec_umem = find_umem_by_id(dev, ureq->dbrec_umem_id);
	if (!dbrec_umem) {
		err = -ENOSPC;
		goto error_out;
	}

	dbrec_dma = ((u64 *)(uintptr_t)dbrec_umem->mtt->buf)[0];
	dbrec_dma += ureq->dbrec_offset;

	obj = kzalloc(sizeof(*obj), GFP_KERNEL);
	if (!obj) {
		err = -ENOMEM;
		goto error_out;
	}

	obj->dev = dev;
	obj->flags = DEVX_OBJ_FLAGS_CQ;
	obj->cq.assoc_eqn = ureq->eqn;
	obj->cq.depth = ureq->depth;
	obj->cq.user_cq.dbrec_dma = dbrec_dma;
	obj->cq.event = devx_cq_event;

	err = ERDMA_ALLOC_RES_ID(dev, cq, &obj->obj_id, &obj->cq, dev->attrs.max_cq,
				 next_alloc_cqn);
	if (err < 0)
		goto free_obj;

	cq_mem = &obj->cq.user_cq.qbuf_mtt;
	err = devx_get_sub_mem(umem, ureq->qbuf_offset, ureq->max_qbuf_len,
			       cq_mem);
	if (err)
		goto free_id;
	/* cq buffer must be 4K aligned */
	if (cq_mem->page_offset & (ERDMA_HW_PAGE_SIZE - 1)) {
		err = -EINVAL;
		goto put_cq_mem;
	}

	obj->devx_umem = umem;

	pr_debug(
		"devx_create_cq: cqn %u, eqn %u, qbuf_off %u, qbuf_len %llu, page_cnt %u, dbrec dma %llx\n",
		obj->obj_id, obj->cq.assoc_eqn, cq_mem->offset, cq_mem->len,
		cq_mem->page_cnt, dbrec_dma);

	erdma_cmdq_build_reqhdr(&req.hdr, CMDQ_SUBMOD_RDMA,
				CMDQ_OPCODE_CREATE_CQ);

	req.cfg0 =
		FIELD_PREP(ERDMA_CMD_CREATE_CQ_CQN_MASK, obj->obj_id) |
		FIELD_PREP(ERDMA_CMD_CREATE_CQ_DEPTH_MASK, ilog2(obj->cq.depth));
	req.cfg1 = FIELD_PREP(ERDMA_CMD_CREATE_CQ_EQN_MASK, obj->cq.assoc_eqn);

	req.cfg0 |= FIELD_PREP(ERDMA_CMD_CREATE_CQ_PAGESIZE_MASK,
			       ilog2(umem->page_size) - ERDMA_HW_PAGE_SHIFT);
	if (cq_mem->mtt_nents == 1) {
		req.qbuf_addr_l =
			lower_32_bits(((u64 *)(uintptr_t)cq_mem->mtt->buf)[0]);
		req.qbuf_addr_h =
			upper_32_bits(((u64 *)(uintptr_t)cq_mem->mtt->buf)[0]);
		req.cfg1 |= FIELD_PREP(ERDMA_CMD_CREATE_CQ_MTT_TYPE_MASK,
				       ERDMA_MR_INLINE_MTT);
	} else {
		req.qbuf_addr_l = lower_32_bits(cq_mem->mtt->buf_dma);
		req.qbuf_addr_h = upper_32_bits(cq_mem->mtt->buf_dma);
		req.cfg1 |= FIELD_PREP(ERDMA_CMD_CREATE_CQ_MTT_TYPE_MASK,
				       ERDMA_MR_INDIRECT_MTT);
	}
	req.cfg1 |=
		FIELD_PREP(ERDMA_CMD_CREATE_CQ_MTT_CNT_MASK, cq_mem->mtt_nents);

	req.first_page_offset = cq_mem->page_offset;
	req.cq_db_info_addr = dbrec_dma;

	err = erdma_post_cmd_wait(&dev->cmdq, &req, sizeof(req), NULL, NULL);
	if (err)
		goto put_cq_mem;

	erdma_stats_add_mtt_nents(dev, cq_mem->mtt_nents,
				  ERDMA_CQ_MTT_INLINE_THRESH);

	return obj;

put_cq_mem:
	if (cq_mem)
		devx_put_sub_mem(cq_mem);

free_id:
	ERDMA_FREE_RES_ID(dev, cq, obj->obj_id);

free_obj:
	kfree(obj);

error_out:
	ERDMA_INC_CNT(dev, CMD_CREATE_CQ_FAILED);

	return ERR_PTR(err);
}

static void devx_assemble_qbuf_mtt_for_cmd(struct erdma_mem *mem, u32 *cfg,
					   u64 *addr0, u64 *addr1)
{
	struct erdma_mtt *mtt = mem->mtt;

	*cfg = mem->page_offset;
	*cfg |= FIELD_PREP(ERDMA_CMD_CREATE_QP_MTT_CNT_MASK, mem->page_cnt);
	if (mem->mtt_nents > ERDMA_MAX_INLINE_MTT_ENTRIES) {
		*addr0 = mtt->buf_dma;
		*cfg |= FIELD_PREP(ERDMA_CMD_CREATE_QP_MTT_TYPE_MASK,
				   ERDMA_MR_INDIRECT_MTT);
	} else {
		*addr0 = ((u64 *)(uintptr_t)mtt->buf)[0];
		memcpy(addr1, mtt->buf + sizeof(dma_addr_t),
		       MTT_SIZE(mem->page_cnt - 1));
		*cfg |= FIELD_PREP(ERDMA_CMD_CREATE_QP_MTT_TYPE_MASK,
				   ERDMA_MR_INLINE_MTT);
	}
}

static int devx_destroy_qp(struct devx_obj *obj)
{
	struct erdma_cmdq_destroy_qp_req req;
	struct erdma_dev *dev = obj->dev;
	int err;

	erdma_cmdq_build_reqhdr(&req.hdr, CMDQ_SUBMOD_RDMA,
				CMDQ_OPCODE_DESTROY_QP);
	req.qpn = obj->obj_id;

	err = erdma_post_cmd_wait(&dev->cmdq, &req, sizeof(req), NULL, NULL);
	if (err)
		return err;

	devx_put_sub_mem(&obj->qp.user_qp.sq_mem);
	devx_put_sub_mem(&obj->qp.user_qp.rq_mem);
	ERDMA_FREE_RES_ID(dev, qp, obj->obj_id);

	return 0;
}

static void devx_qp_event(struct erdma_qp *qp, enum ib_event_type event_type)
{
	pr_debug("devx_qp_event: qp %p, event_type %u.\n", qp, event_type);
}

static struct devx_obj *
devx_create_qp(struct erdma_dev *dev,
	       struct erdma_devx_create_object_qp_req *ureq)
{
	u32 sq_size, rq_size, sq_start, sq_end, rq_start, rq_end;
	struct erdma_cmdq_create_qp_req req;
	struct devx_umem *wq_umem, *dbrec_umem;
	struct erdma_mem *sq_mem, *rq_mem;
	struct devx_obj *obj;
	u64 resp0, resp1;
	u64 dbrec_dma;
	int err = -EINVAL;

	pr_debug(
		"devx_create_qp in0: pdn:%u, umem_id:%u, offset:%u, sqdepth:%u, sqwqesize:%u, rqdepth:%u, rqwqesize:%u\n",
		ureq->pdn, ureq->wq_umem_id, ureq->wq_offset, ureq->sq_depth, ureq->sq_wqe_size,
		ureq->rq_depth, ureq->rq_wqe_size);

	pr_debug(
		"devx_create_qp in1: wq_len:%u, scqn:%u, rcqn:%u, dbrec_umem_id:%u, dbrec_offset:%u\n",
		ureq->wq_max_len, ureq->scqn, ureq->rcqn, ureq->dbrec_umem_id,
		ureq->dbrec_offset);

	if ((ureq->sq_depth > dev->attrs.max_send_wr) ||
	    (ureq->rq_depth > dev->attrs.max_recv_wr) ||
	    (ureq->sq_wqe_size > ERDMA_MAX_WQEBB_PER_SQE) ||
	    (ureq->rq_wqe_size > 1) || !ureq->sq_depth ||
	    !ureq->sq_wqe_size || !ureq->rq_depth || !ureq->rq_wqe_size) {
		err = -EINVAL;
		goto error_out;
	}

	obj = kzalloc(sizeof(*obj), GFP_KERNEL);
	if (!obj) {
		err = -ENOMEM;
		goto error_out;
	}

	err = ERDMA_ALLOC_RES_ID(dev, qp, &obj->obj_id, &obj->qp, dev->attrs.max_qp,
				 next_alloc_qpn);
	if (err < 0) {
		goto free_obj;
	}

	wq_umem = find_umem_by_id(dev, ureq->wq_umem_id);
	if (!wq_umem) {
		err = -ENOSPC;
		goto free_idx;
	}

	dbrec_umem = find_umem_by_id(dev, ureq->dbrec_umem_id);
	if (!dbrec_umem) {
		err = -ENOSPC;
		goto free_idx;
	}

	dbrec_dma = ((u64 *)(uintptr_t)dbrec_umem->mtt->buf)[0];
	dbrec_dma += ureq->dbrec_offset;

	sq_size = ureq->sq_depth * ureq->sq_wqe_size;
	if (!is_power_of_2(sq_size)) {
		pr_err("devx_create_qp: sq_depth(%u), sq_wqe_size(%u), sq size is not power of 2.\n",
			ureq->sq_depth, ureq->sq_wqe_size);
		err = -EINVAL;
		goto free_idx;
	}

	rq_size = ureq->rq_depth * ureq->rq_wqe_size;
	if (!is_power_of_2(rq_size)) {
		pr_err("devx_create_qp: rq_depth(%u), rq_wqe_size(%u), rq size is not power of 2.\n",
			ureq->rq_depth, ureq->rq_wqe_size);
		err = -EINVAL;
		goto free_idx;
	}

	sq_start = ureq->wq_offset;
	sq_end = ureq->wq_offset + (sq_size << SQEBB_SHIFT);
	rq_start = sq_end;
	rq_end = rq_start + (rq_size << RQE_SHIFT);
	if (rq_end - sq_start > ureq->wq_max_len) {
		pr_err("devx_create_qp: wq is too large(%u > %u)\n",
		       rq_end - sq_end, ureq->wq_max_len);
		err = -EINVAL;
		goto free_idx;
	}

	sq_mem = &obj->qp.user_qp.sq_mem;
	err = devx_get_sub_mem(wq_umem, sq_start, sq_end - sq_start, sq_mem);
	if (err)
		goto free_idx;

	rq_mem = &obj->qp.user_qp.rq_mem;
	err = devx_get_sub_mem(wq_umem, rq_start, rq_end - rq_start, rq_mem);
	if (err)
		goto put_sq_mem;

	obj->dev = dev;
	obj->flags = DEVX_OBJ_FLAGS_QP;
	obj->devx_umem = wq_umem;
	obj->qp.attrs.cc = dev->attrs.cc;
	obj->qp.attrs.sq_size = sq_size;
	obj->qp.attrs.rq_size = rq_size;
	obj->qp.attrs.state = ERDMA_QP_STATE_IDLE;
	obj->qp.event = devx_qp_event;

	erdma_cmdq_build_reqhdr(&req.hdr, CMDQ_SUBMOD_RDMA,
				CMDQ_OPCODE_CREATE_QP);

	/* SQ size need to (* wqebb count) */
	req.cfg0 = FIELD_PREP(ERDMA_CMD_CREATE_QP_SQ_DEPTH_MASK, ilog2(sq_size)) |
		   FIELD_PREP(ERDMA_CMD_CREATE_QP_QPN_MASK, obj->obj_id);
	req.cfg1 = FIELD_PREP(ERDMA_CMD_CREATE_QP_RQ_DEPTH_MASK, ilog2(rq_size)) |
		   FIELD_PREP(ERDMA_CMD_CREATE_QP_PD_MASK, ureq->pdn);

	req.sq_cqn_mtt_cfg =
		FIELD_PREP(ERDMA_CMD_CREATE_QP_PAGE_SIZE_MASK,
			   ilog2(sq_mem->page_size) - ERDMA_HW_PAGE_SHIFT) |
		FIELD_PREP(ERDMA_CMD_CREATE_QP_CQN_MASK, ureq->scqn);

	req.rq_cqn_mtt_cfg =
		FIELD_PREP(ERDMA_CMD_CREATE_QP_PAGE_SIZE_MASK,
			   ilog2(rq_mem->page_size) - ERDMA_HW_PAGE_SHIFT) |
		FIELD_PREP(ERDMA_CMD_CREATE_QP_CQN_MASK, ureq->rcqn);

	devx_assemble_qbuf_mtt_for_cmd(sq_mem, &req.sq_mtt_cfg,
				       &req.sq_buf_addr, req.sq_mtt_entry);
	devx_assemble_qbuf_mtt_for_cmd(rq_mem, &req.rq_mtt_cfg,
				       &req.rq_buf_addr, req.rq_mtt_entry);

	req.sq_dbrec_dma = dbrec_dma;
	req.rq_dbrec_dma = dbrec_dma + 8;

	err = erdma_post_cmd_wait(&dev->cmdq, &req, sizeof(req), &resp0,
				  &resp1);
	if (err)
		goto put_rq_mem;

	return obj;

put_rq_mem:
	if (rq_mem)
		devx_put_sub_mem(rq_mem);

put_sq_mem:
	if (sq_mem)
		devx_put_sub_mem(sq_mem);

free_idx:
	ERDMA_FREE_RES_ID(dev, qp, obj->obj_id);

free_obj:
	kfree(obj);

error_out:
	ERDMA_INC_CNT(dev, CMD_CREATE_QP_FAILED);

	return ERR_PTR(err);
}

static int
UVERBS_HANDLER(ERDMA_METHOD_DEVX_OBJ_CREATE)(struct uverbs_attr_bundle *attrs)
{
	struct erdmadv_devx_obj_create_param_in *cmd;
	struct erdmadv_devx_obj_create_param_out out;
	struct ib_uobject *uobj = uverbs_attr_get_uobject(
		attrs, ERDMA_ATTR_DEVX_OBJ_CREATE_HANDLE);
	struct erdma_ucontext *c = rdma_udata_to_drv_context(
		&attrs->driver_udata, struct erdma_ucontext, ibucontext);
	struct erdma_dev *dev = to_edev(c->ibucontext.device);
	struct devx_obj *obj;
	u32 type;
	int err;

	if (uverbs_copy_from(&type, attrs, ERDMA_ATTR_DEVX_OBJ_CREATE_TYPE))
		return -EINVAL;

	cmd = uverbs_attr_get_alloced_ptr(attrs,
					  ERDMA_ATTR_DEVX_OBJ_CREATE_CMD_IN);

	pr_debug("ERDMA_METHOD_DEVX_OBJ_CREATE type %d\n", type);

	if (type == ERDMA_DEVX_OBJ_TYPE_CQ) {
		obj = devx_create_cq(dev, &cmd->cq);
		if (IS_ERR(obj))
			return PTR_ERR(obj);
	} else if (type == ERDMA_DEVX_OBJ_TYPE_QP) {
		obj = devx_create_qp(dev, &cmd->qp);
		if (IS_ERR(obj))
			return PTR_ERR(obj);
	} else {
		return -EINVAL;
	}

	uobj->object = obj;

	out.obj_id = obj->obj_id;
	err = uverbs_copy_to(attrs, ERDMA_ATTR_DEVX_OBJ_CREATE_CMD_OUT, &out,
			     sizeof(out));
	if (err)
		goto obj_destroy;

	return 0;

obj_destroy:
	if (type == ERDMA_DEVX_OBJ_TYPE_CQ)
		devx_destroy_cq(obj);
	else if (type == ERDMA_DEVX_OBJ_TYPE_QP)
		devx_destroy_qp(obj);

	return err;
}

static int devx_modify_qp_to_error(struct devx_obj *obj)
{
	struct erdma_cmdq_modify_qp_req req;
	struct erdma_dev *dev = obj->dev;

	erdma_cmdq_build_reqhdr(&req.hdr, CMDQ_SUBMOD_RDMA,
				CMDQ_OPCODE_MODIFY_QP);

	req.cfg = FIELD_PREP(ERDMA_CMD_MODIFY_QP_STATE_MASK,
			     ERDMA_QP_STATE_ERROR) |
		  FIELD_PREP(ERDMA_CMD_MODIFY_QP_QPN_MASK, obj->obj_id);

	return erdma_post_cmd_wait(&dev->cmdq, &req, sizeof(req), NULL, NULL);
}

static int devx_modify_qp_to_rtr(struct erdma_dev *dev, struct devx_obj *obj,
				 struct erdma_devx_modify_object_qp_req *ureq)
{
	struct erdma_cmdq_modify_qp_req req;
	union {
		struct sockaddr_in6 in6;
		struct sockaddr_in in;
	} raddr, laddr;
	union ib_gid dgid, sgid;

	dgid.global.interface_id = ureq->dgid_interface_id;
	dgid.global.subnet_prefix = ureq->dgid_subnet_prefix;

	sgid.global.interface_id = ureq->sgid_interface_id;
	sgid.global.subnet_prefix = ureq->sgid_subnet_prefix;

	rdma_gid2ip((struct sockaddr *)&raddr, &dgid);
	rdma_gid2ip((struct sockaddr *)&laddr, &sgid);

	pr_debug("local_gid_index %u, sgid %pI6, laddr 0x%x, lqpn %u\n",
		 ureq->local_gid_index, sgid.raw,
		 ntohl(laddr.in.sin_addr.s_addr), obj->obj_id);
	pr_debug("dgid %pI6, raddr 0x%x, remote_qpn %u\n", dgid.raw,
		 ntohl(raddr.in.sin_addr.s_addr), ureq->remote_qpn);

	erdma_cmdq_build_reqhdr(&req.hdr, CMDQ_SUBMOD_RDMA,
				CMDQ_OPCODE_MODIFY_QP);

	req.cfg =
		FIELD_PREP(ERDMA_CMD_MODIFY_QP_STATE_MASK, ERDMA_QP_STATE_RTS) |
		FIELD_PREP(ERDMA_CMD_MODIFY_QP_CC_MASK, dev->attrs.cc) |
		FIELD_PREP(ERDMA_CMD_MODIFY_QP_QPN_MASK, obj->obj_id);
	req.cookie =
		FIELD_PREP(ERDMA_CMD_MODIFY_QP_RQPN_MASK, ureq->remote_qpn) |
		FIELD_PREP(ERDMA_CMD_MODIFY_QP_TLP_MASK, 1);

	if (((struct sockaddr_in *)&raddr)->sin_family == AF_INET) {
		req.dip = raddr.in.sin_addr.s_addr;
		req.sip = laddr.in.sin_addr.s_addr;
	} else {
		return -EAFNOSUPPORT;
	}

	erdma_gen_port_from_qpn(req.sip, req.dip, obj->obj_id, ureq->remote_qpn,
				&req.sport, &req.dport);
	req.sport = htons(req.sport);
	req.dport = htons(req.dport);

	req.send_nxt = req.sport * 4;
	req.recv_nxt = req.dport * 4;

	req.cookie |= FIELD_PREP(ERDMA_CMD_MODIFY_QP_WWI_PERF_MASK, 1);

	return erdma_post_cmd_wait(&dev->cmdq, &req, sizeof(req), NULL, NULL);
}

static int
UVERBS_HANDLER(ERDMA_METHOD_DEVX_OBJ_MODIFY)(struct uverbs_attr_bundle *attrs)
{
	struct erdmadv_devx_obj_modify_param_in *cmd;
	struct erdmadv_devx_obj_modify_param_out *out;
	struct ib_uobject *uobj = uverbs_attr_get_uobject(
		attrs, ERDMA_ATTR_DEVX_OBJ_MODIFY_HANDLE);
	struct erdma_ucontext *c = rdma_udata_to_drv_context(
		&attrs->driver_udata, struct erdma_ucontext, ibucontext);
	struct erdma_dev *dev = to_edev(c->ibucontext.device);
	struct devx_obj *obj = uobj->object;
	uint32_t type;
	int err = 0, err2;

	if (uverbs_copy_from(&type, attrs, ERDMA_ATTR_DEVX_OBJ_MODIFY_TYPE))
		return -EINVAL;

	if (type != ERDMA_DEVX_OBJ_TYPE_QP)
		return -ENOTSUPP;

	if (obj->flags != DEVX_OBJ_FLAGS_QP) {
		pr_err("Wrong obj type (%u) for modify\n", obj->flags);
		return -ENOSPC;
	}

	cmd = uverbs_attr_get_alloced_ptr(attrs,
					  ERDMA_ATTR_DEVX_OBJ_MODIFY_CMD_IN);

	out = uverbs_zalloc(attrs, sizeof(*out));
	if (IS_ERR(out))
		return PTR_ERR(out);

	if (cmd->qp.op == ERDMA_DEVX_OBJ_MODIFY_QP_OP_RST2INIT) {
		pr_debug("devx_obj_modify RST2INIT, nothing to do\n");
		err = 0;
	} else if (cmd->qp.op == ERDMA_DEVX_OBJ_MODIFY_QP_OP_INIT2RTR) {
		err = devx_modify_qp_to_rtr(dev, obj, &cmd->qp);
	} else if (cmd->qp.op == ERDMA_DEVX_OBJ_MODIFY_QP_OP_RTR2RTS) {
		pr_debug("devx_obj_modify RTR2RTS, nothing to do\n");
		err = 0;
	} else {
		err = -ENOTSUPP;
	}

	err2 = uverbs_copy_to(attrs, ERDMA_ATTR_DEVX_OBJ_MODIFY_CMD_OUT, out,
			      sizeof(*out));

	return err2 ?: err;
}

static int devx_obj_cleanup(struct ib_uobject *uobject,
			    enum rdma_remove_reason why,
			    struct uverbs_attr_bundle *attrs)
{
	struct devx_obj *obj = uobject->object;
	int ret = 0;

	pr_debug("erdma_obj_cleanup obj_flags:%x, reason %d.\n", obj->flags, why);

	if (obj->flags & DEVX_OBJ_FLAGS_CQ) {
		ret = devx_destroy_cq(obj);
	} else if (obj->flags & DEVX_OBJ_FLAGS_QP) {
		devx_modify_qp_to_error(obj);
		ret = devx_destroy_qp(obj);
	}

	if (ret)
		return ret;

	kfree(obj);

	return 0;
}

DECLARE_UVERBS_NAMED_METHOD(
	ERDMA_METHOD_DEVX_OBJ_CREATE,
	UVERBS_ATTR_IDR(ERDMA_ATTR_DEVX_OBJ_CREATE_HANDLE,
			ERDMA_OBJECT_DEVX_OBJ, UVERBS_ACCESS_NEW, UA_MANDATORY),
	UVERBS_ATTR_PTR_IN(ERDMA_ATTR_DEVX_OBJ_CREATE_TYPE,
			   UVERBS_ATTR_TYPE(u32), UA_MANDATORY),
	UVERBS_ATTR_PTR_IN(ERDMA_ATTR_DEVX_OBJ_CREATE_CMD_IN,
			   UVERBS_ATTR_MIN_SIZE(128), UA_MANDATORY,
			   UA_ALLOC_AND_COPY),
	UVERBS_ATTR_PTR_OUT(ERDMA_ATTR_DEVX_OBJ_CREATE_CMD_OUT,
			    UVERBS_ATTR_MIN_SIZE(32), UA_MANDATORY));

DECLARE_UVERBS_NAMED_METHOD(
	ERDMA_METHOD_DEVX_OBJ_MODIFY,
	UVERBS_ATTR_IDR(ERDMA_ATTR_DEVX_OBJ_MODIFY_HANDLE,
			UVERBS_IDR_ANY_OBJECT, UVERBS_ACCESS_WRITE,
			UA_MANDATORY),
	UVERBS_ATTR_PTR_IN(ERDMA_ATTR_DEVX_OBJ_MODIFY_TYPE,
			   UVERBS_ATTR_TYPE(u32), UA_MANDATORY),
	UVERBS_ATTR_PTR_IN(ERDMA_ATTR_DEVX_OBJ_MODIFY_CMD_IN,
			   UVERBS_ATTR_MIN_SIZE(128), UA_MANDATORY,
			   UA_ALLOC_AND_COPY),
	UVERBS_ATTR_PTR_OUT(ERDMA_ATTR_DEVX_OBJ_MODIFY_CMD_OUT,
			    UVERBS_ATTR_MIN_SIZE(32), UA_MANDATORY));

DECLARE_UVERBS_NAMED_METHOD_DESTROY(
	ERDMA_METHOD_DEVX_OBJ_DESTROY,
	UVERBS_ATTR_IDR(ERDMA_ATTR_DEVX_OBJ_DESTROY_HANDLE,
			ERDMA_OBJECT_DEVX_OBJ, UVERBS_ACCESS_DESTROY,
			UA_MANDATORY));

DECLARE_UVERBS_NAMED_OBJECT(ERDMA_OBJECT_DEVX_OBJ,
			    UVERBS_TYPE_ALLOC_IDR(devx_obj_cleanup),
			    &UVERBS_METHOD(ERDMA_METHOD_DEVX_OBJ_CREATE),
			    &UVERBS_METHOD(ERDMA_METHOD_DEVX_OBJ_MODIFY),
			    &UVERBS_METHOD(ERDMA_METHOD_DEVX_OBJ_DESTROY));

static int devx_umem_get(struct erdma_dev *dev, struct ib_ucontext *ucontext,
			 struct uverbs_attr_bundle *attrs,
			 struct devx_umem *obj)
{
	struct ib_block_iter biter;
	struct erdma_mtt *mtt;
	dma_addr_t *page_list;
	u32 idx = 0;
	u64 addr;
	size_t size;
	u32 access;
	int err;

	if (uverbs_copy_from(&addr, attrs, ERDMA_ATTR_DEVX_UMEM_REG_ADDR) ||
	    uverbs_copy_from(&size, attrs, ERDMA_ATTR_DEVX_UMEM_REG_LEN))
		return -EFAULT;

	err = uverbs_get_flags32(
		&access, attrs, ERDMA_ATTR_DEVX_UMEM_REG_ACCESS,
		IB_UVERBS_ACCESS_LOCAL_WRITE | IB_UVERBS_ACCESS_REMOTE_WRITE |
			IB_UVERBS_ACCESS_REMOTE_READ);
	if (err)
		return err;
#ifdef HAVE_IB_CHECK_MR_ACCESS_TWO_PARAMS
	err = ib_check_mr_access(&dev->ibdev, access);
#else
	err = ib_check_mr_access(access);
#endif
	if (err)
		return err;

	obj->umem =
#ifdef HAVE_IB_UMEM_GET_PEER_DEVICE
		ib_umem_get_peer(&dev->ibdev, addr, size, access, 0);
#elif defined(HAVE_IB_UMEM_GET_PEER_UDATA)
		ib_umem_get_peer(&attrs->driver_udata, addr, size, access, 0);
#elif defined(HAVE_IB_UMEM_GET_DEVICE_PARAM)
		ib_umem_get(&dev->ibdev, addr, size, access);
#elif defined(HAVE_IB_UMEM_GET_NO_DMASYNC)
		ib_umem_get(&attrs->driver_udata, addr, size, access);
#elif defined(HAVE_IB_UMEM_GET_UDATA)
		ib_umem_get(&attrs->driver_udata, addr, size, access, 0);
#else
		ib_umem_get(ucontext, addr, size, access, 0);
#endif
	if (IS_ERR(obj->umem))
		return PTR_ERR(obj->umem);

	obj->access = to_erdma_access_flags(access);
	obj->page_size =
		ib_umem_find_best_pgsz(obj->umem, SZ_4K, obj->umem->address);
	obj->npages = ib_umem_num_dma_blocks(obj->umem, obj->page_size);

	ibdev_dbg(
		&dev->ibdev,
		"devx_umem_get: is_peer %u, addr:%llx, size:%lu, page size %lu, npages %lu\n",
#if defined(HAVE_IB_UMEM_GET_PEER_DEVICE) || \
	defined(HAVE_IB_UMEM_GET_PEER_UDATA)
		obj->umem->is_peer,
#else
		0,
#endif
		addr, size, obj->page_size, obj->npages);

	if (!obj->npages) {
		ib_umem_release(obj->umem);
		return -EINVAL;
	}

	obj->page_offset = obj->umem->address & (obj->page_size - 1);

	mtt = erdma_create_mtt(dev, MTT_SIZE(obj->npages), false);
	if (IS_ERR(obj->mtt)) {
		err = PTR_ERR(obj->mtt);
		goto error_ret;
	}

	obj->mtt = mtt;

	while (mtt->low_level)
		mtt = mtt->low_level;

	page_list = mtt->buf;

	rdma_umem_for_each_dma_block(obj->umem, &biter, obj->page_size)
		page_list[idx++] = rdma_block_iter_dma_address(&biter);

	return 0;

error_ret:
	ib_umem_release(obj->umem);

	return err;
}

static int
UVERBS_HANDLER(ERDMA_METHOD_DEVX_UMEM_REG)(struct uverbs_attr_bundle *attrs)
{
	struct devx_umem *obj;
	struct ib_uobject *uobj =
		uverbs_attr_get_uobject(attrs, ERDMA_ATTR_DEVX_UMEM_REG_HANDLE);
	u32 obj_id;
	struct erdma_ucontext *c = rdma_udata_to_drv_context(
		&attrs->driver_udata, struct erdma_ucontext, ibucontext);
	struct erdma_dev *dev = to_edev(c->ibucontext.device);
	int err;

	obj = kzalloc(sizeof(struct devx_umem), GFP_KERNEL);
	if (!obj)
		return -ENOMEM;

	err = ERDMA_ALLOC_RES_ID(dev, umem, &obj->umem_id, obj,
				 dev->attrs.max_umem, next_alloc_umem_id);
	if (err < 0)
		goto err_obj_free;

	err = devx_umem_get(dev, &c->ibucontext, attrs, obj);
	if (err)
		goto err_alloc_res;

	obj->dev = dev;
	uobj->object = obj;
	obj_id = obj->umem_id;

	err = uverbs_copy_to(attrs, ERDMA_ATTR_DEVX_UMEM_REG_OUT_ID, &obj_id,
			     sizeof(obj_id));
	if (err)
		goto err_umem_release;

	return err;

err_umem_release:
	ib_umem_release(obj->umem);

err_alloc_res:
	ERDMA_FREE_RES_ID(dev, umem, obj->umem_id);

err_obj_free:
	kfree(obj);
	return err;
}

static int devx_umem_cleanup(struct ib_uobject *uobject,
			     enum rdma_remove_reason why,
			     struct uverbs_attr_bundle *attrs)
{
	struct devx_umem *obj = uobject->object;
	struct erdma_dev *dev = obj->dev;

	pr_debug("devx_umem_cleanup dev %p, umem_id %u, reason %d.\n", dev, obj->umem_id, why);

	erdma_destroy_mtt(dev, obj->mtt);
	ib_umem_release(obj->umem);
	ERDMA_FREE_RES_ID(dev, umem, obj->umem_id);

	kfree(obj);
	return 0;
}

DECLARE_UVERBS_NAMED_METHOD(
	ERDMA_METHOD_DEVX_UMEM_REG,
	UVERBS_ATTR_IDR(ERDMA_ATTR_DEVX_UMEM_REG_HANDLE, ERDMA_OBJECT_DEVX_UMEM,
			UVERBS_ACCESS_NEW, UA_MANDATORY),
	UVERBS_ATTR_PTR_IN(ERDMA_ATTR_DEVX_UMEM_REG_ADDR, UVERBS_ATTR_TYPE(u64),
			   UA_MANDATORY),
	UVERBS_ATTR_PTR_IN(ERDMA_ATTR_DEVX_UMEM_REG_LEN, UVERBS_ATTR_TYPE(u64),
			   UA_MANDATORY),
	UVERBS_ATTR_FLAGS_IN(ERDMA_ATTR_DEVX_UMEM_REG_ACCESS,
			     enum ib_access_flags),
	UVERBS_ATTR_PTR_OUT(ERDMA_ATTR_DEVX_UMEM_REG_OUT_ID,
			    UVERBS_ATTR_TYPE(u32), UA_MANDATORY));

DECLARE_UVERBS_NAMED_METHOD_DESTROY(
	ERDMA_METHOD_DEVX_UMEM_DEREG,
	UVERBS_ATTR_IDR(ERDMA_ATTR_DEVX_UMEM_DEREG_HANDLE,
			ERDMA_OBJECT_DEVX_UMEM, UVERBS_ACCESS_DESTROY,
			UA_MANDATORY));

DECLARE_UVERBS_NAMED_OBJECT(ERDMA_OBJECT_DEVX_UMEM,
			    UVERBS_TYPE_ALLOC_IDR(devx_umem_cleanup),
			    &UVERBS_METHOD(ERDMA_METHOD_DEVX_UMEM_REG),
			    &UVERBS_METHOD(ERDMA_METHOD_DEVX_UMEM_DEREG));

const struct uapi_definition erdma_devx_defs[] = {
	UAPI_DEF_CHAIN_OBJ_TREE_NAMED(ERDMA_OBJECT_DEVX),
	UAPI_DEF_CHAIN_OBJ_TREE_NAMED(ERDMA_OBJECT_DEVX_OBJ),
	UAPI_DEF_CHAIN_OBJ_TREE_NAMED(ERDMA_OBJECT_DEVX_UMEM),
	{}
};
#endif
