// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

/* Authors: Cheng Xu <chengyou@linux.alibaba.com> */
/*          Kai Shen <kaishen@linux.alibaba.com> */
/* Copyright (c) 2020-2022, Alibaba Group. */

#include <linux/types.h>

#include "erdma.h"

int erdma_query_resource(struct erdma_dev *dev, u32 mod, u32 op, u32 index,
			 void *out, u32 len)
{
	struct erdma_cmdq_query_req req;
	dma_addr_t dma_addr;
	void *resp;
	int err;

	erdma_cmdq_build_reqhdr(&req.hdr, mod, op);

	resp = dma_pool_alloc(dev->resp_pool, GFP_KERNEL | __GFP_ZERO,
			      &dma_addr);
	if (!resp)
		return -ENOMEM;

	req.index = index;
	req.target_addr = dma_addr;
	req.target_length = ERDMA_HW_RESP_SIZE;

	err = erdma_post_cmd_wait(&dev->cmdq, &req, sizeof(req), NULL, NULL);
	if (err)
		goto out;

	if (out)
		memcpy(out, resp, len);

out:
	dma_pool_free(dev->resp_pool, resp, dma_addr);

	return err;
}

int erdma_query_ext_attr(struct erdma_dev *dev, void *out)
{
	BUILD_BUG_ON(sizeof(struct erdma_cmdq_query_ext_attr_resp) >
		     ERDMA_HW_RESP_SIZE);

	return erdma_query_resource(
		dev, CMDQ_SUBMOD_COMMON, CMDQ_OPCODE_GET_EXT_ATTR, 0, out,
		sizeof(struct erdma_cmdq_query_ext_attr_resp));
}

int erdma_set_ext_attr(struct erdma_dev *dev, struct erdma_ext_attr *attr)
{
	struct erdma_cmdq_set_ext_attr_req req;
	int ret;

	erdma_cmdq_build_reqhdr(&req.hdr, CMDQ_SUBMOD_COMMON,
				CMDQ_OPCODE_SET_EXT_ATTR);

	memcpy(&req.attr, attr, sizeof(*attr));

	ret = erdma_post_cmd_wait(&dev->cmdq, &req, sizeof(req), NULL, NULL);

	return ret;
}

int erdma_set_dack_count(struct erdma_dev *dev, u32 value)
{
	struct erdma_ext_attr attr;

	if (value > 0xff)
		return -EINVAL;

	attr.attr_mask = ERDMA_EXT_ATTR_DACK_COUNT_MASK;
	attr.dack_count = (u8)value;

	return erdma_set_ext_attr(dev, &attr);
}

int erdma_enable_legacy_mode(struct erdma_dev *dev, u32 value)
{
	struct erdma_ext_attr attr;

	attr.attr_mask = ERDMA_EXT_ATTR_LEGACY_MODE_MASK;
	attr.enable = value != 0 ? 1 : 0;

	return erdma_set_ext_attr(dev, &attr);
}
