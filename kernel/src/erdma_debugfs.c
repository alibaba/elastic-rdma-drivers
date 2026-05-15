// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

/* Authors: Cheng Xu <chengyou@linux.alibaba.com> */
/*          Kai Shen <kaishen@linux.alibaba.com> */
/* Copyright (c) 2020-2022, Alibaba Group. */

#include <linux/fs.h>
#include <linux/module.h>
#include <linux/debugfs.h>

#include "erdma.h"

struct dentry *erdma_debugfs_root;
EXPORT_SYMBOL(erdma_debugfs_root);

static int erdma_query_cc_profiler_list(struct erdma_dev *dev, void *out)
{
	BUILD_BUG_ON(sizeof(struct erdma_cmdq_query_cc_profiler_list_resp) >
		     ERDMA_HW_RESP_SIZE);

	return erdma_query_resource(dev, CMDQ_SUBMOD_COMMON,
				    CMDQ_OPCODE_QUERY_CC_PROFILER_LIST, 0, out,
				    sizeof(struct erdma_cmdq_query_cc_profiler_list_resp));
}

static int erdma_query_cc_profiler_name(struct erdma_dev *dev, u32 index, void *out)
{
	BUILD_BUG_ON(sizeof(struct erdma_cmdq_query_cc_profiler_name_resp) >
		     ERDMA_HW_RESP_SIZE);

	return erdma_query_resource(dev, CMDQ_SUBMOD_COMMON,
				    CMDQ_OPCODE_QUERY_CC_PROFILER_NAME, index, out,
				    sizeof(struct erdma_cmdq_query_cc_profiler_name_resp));
}

static int erdma_set_cc_profiler(struct erdma_dev *dev, u32 value)
{
	struct erdma_ext_attr attr;

	attr.attr_mask = ERDMA_EXT_ATTR_CC_PROFILER_MASK;
	attr.enable = value < (u32)ERDMA_HW_CC_PROFILER_NUM ? 1 : 0;
	attr.cc_profiler = (u16)value;

	return erdma_set_ext_attr(dev, &attr);
}

static ssize_t tlp_read(struct file *filp, char __user *buf, size_t count,
			 loff_t *pos)
{
	struct erdma_cmdq_query_ext_attr_resp resp;
	struct erdma_dev *dev;
	char cbuf[40];
	int ret;

	dev = filp->private_data;
	ret = erdma_query_ext_attr(dev, &resp);
	if (ret)
		return ret;

	ret = snprintf(cbuf, sizeof(cbuf), "%d\n", (resp.attr_mask & ERDMA_EXT_ATTR_TLP_MASK) != 0);

	return simple_read_from_buffer(buf, count, pos, cbuf, ret);
}

static ssize_t tlp_write(struct file *filp, const char __user *buf,
			  size_t count, loff_t *pos)
{
	struct erdma_ext_attr attr;
	struct erdma_dev *dev;
	u32 var;
	int ret;

	dev = filp->private_data;

	if (kstrtouint_from_user(buf, count, 0, &var))
		return -EFAULT;

	attr.attr_mask = ERDMA_EXT_ATTR_TLP_MASK;
	attr.enable = var != 0 ? 1 : 0;

	ret = erdma_set_ext_attr(dev, &attr);
	if (ret)
		return ret;

	return count;
}

static const struct file_operations tlp_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = tlp_read,
	.write = tlp_write,
};

static ssize_t dack_read(struct file *filp, char __user *buf, size_t count,
			 loff_t *pos)
{
	struct erdma_cmdq_query_ext_attr_resp resp;
	struct erdma_dev *dev;
	char cbuf[20];
	int ret;

	dev = filp->private_data;
	ret = erdma_query_ext_attr(dev, &resp);
	if (ret)
		return ret;

	ret = snprintf(cbuf, sizeof(cbuf), "0x%x\n", resp.dack_count);

	return simple_read_from_buffer(buf, count, pos, cbuf, ret);
}

static ssize_t dack_write(struct file *filp, const char __user *buf,
			  size_t count, loff_t *pos)
{
	struct erdma_dev *dev;
	u32 var;
	int ret;

	dev = filp->private_data;

	if (kstrtouint_from_user(buf, count, 0, &var))
		return -EFAULT;

	ret = erdma_set_dack_count(dev, var);
	if (ret)
		return ret;

	return count;
}

static const struct file_operations dack_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = dack_read,
	.write = dack_write,
};

static ssize_t
cc_profiler_list_read(struct file *filp, char __user *buf, size_t count, loff_t *pos)
{
	struct erdma_cmdq_query_cc_profiler_list_resp list_resp;
	struct erdma_cmdq_query_cc_profiler_name_resp name_resp;
	struct erdma_dev *dev = filp->private_data;
	unsigned long size;
	int len = 0;
	int ret, i;
	char *cbuf;

	/* It takes 6 bytes to hold up to 4 numerals 1 colon and 1 line break. */
	size = ERDMA_HW_CC_PROFILER_NUM * (ERDMA_HW_CC_PROFILER_NAME_LEN + 6);
	cbuf = vmalloc(size);
	if (!cbuf)
		return -ENOMEM;

	ret = erdma_query_cc_profiler_list(dev, &list_resp);
	if (ret)
		goto free_vm;

	for (i = 0; i < ERDMA_HW_CC_PROFILER_NUM; i++) {
		if (list_resp.idx_mask[i / 32] & ((u32)1 << (i % 32))) {
			ret = erdma_query_cc_profiler_name(dev, i, &name_resp);
			if (ret)
				goto free_vm;
			if (name_resp.valid) {
				name_resp.name[ERDMA_HW_CC_PROFILER_NAME_LEN - 1] = '\0';
				len += snprintf(cbuf + len, size - len, "%d:%s\n", i, name_resp.name);
			}
		}
	}

	ret = simple_read_from_buffer(buf, count, pos, cbuf, len);

free_vm:
	vfree(cbuf);
	return ret;
}

static const struct file_operations cc_profiler_list_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = cc_profiler_list_read,
};

static ssize_t
cc_profiler_read(struct file *filp, char __user *buf, size_t count, loff_t *pos)
{
	struct erdma_cmdq_query_ext_attr_resp resp;
	struct erdma_dev *dev = filp->private_data;
	char cbuf[20];
	int ret;

	ret = erdma_query_ext_attr(dev, &resp);
	if (ret)
		return ret;

	if (resp.cap_mask & ERDMA_EXT_ATTR_CC_PROFILER_MASK &&
	    resp.attr_mask & ERDMA_EXT_ATTR_CC_PROFILER_MASK)
		ret = snprintf(cbuf, sizeof(cbuf), "%d\n", resp.cc_profiler);
	else
		ret = snprintf(cbuf, sizeof(cbuf), "Invalid\n");

	return simple_read_from_buffer(buf, count, pos, cbuf, ret);
}

static ssize_t cc_profiler_write(struct file *filp, const char __user *buf,
			  size_t count, loff_t *pos)
{
	struct erdma_dev *dev = filp->private_data;
	u32 var;
	int ret;

	if (kstrtouint_from_user(buf, count, 0, &var))
		return -EFAULT;

	ret = erdma_set_cc_profiler(dev, var);
	if (ret)
		return ret;

	return count;
}

static const struct file_operations cc_profiler_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.write = cc_profiler_write,
	.read = cc_profiler_read,
};

static ssize_t cap_read(struct file *filp, char __user *buf, size_t count,
			 loff_t *pos)
{
	struct erdma_cmdq_query_ext_attr_resp resp;
	struct erdma_dev *dev;
	char cbuf[40];
	int ret;

	dev = filp->private_data;
	ret = erdma_query_ext_attr(dev, &resp);
	if (ret)
		return ret;

	ret = snprintf(cbuf, sizeof(cbuf), "cap 0x%lx\next_cap 0x%x\n",
		       dev->attrs.cap_flags, resp.cap_mask);

	return simple_read_from_buffer(buf, count, pos, cbuf, ret);
}

static const struct file_operations cap_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = cap_read,
};

static ssize_t mtte_usage_read(struct file *filp, char __user *buf, size_t count,
			 loff_t *pos)
{
	struct erdma_dev *dev;
	char cbuf[40];
	int ret;

	dev = filp->private_data;

	ret = snprintf(cbuf, sizeof(cbuf), "%u/%u\n",
		       atomic_read(&dev->num_mtte), dev->attrs.max_mtte);

	return simple_read_from_buffer(buf, count, pos, cbuf, ret);
}

static const struct file_operations mtte_usage_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = mtte_usage_read,
};

int erdma_debugfs_files_create(struct erdma_dev *dev)
{
	struct dentry *ent;

	if (!erdma_debugfs_root)
		return 0;

	dev->dbg_root = debugfs_create_dir(dev_name(&dev->pdev->dev), erdma_debugfs_root);
	if (!dev->dbg_root) {
		dev_err(&dev->pdev->dev, "erdma: Cannot create debugfs dir, aborting\n");
		return -ENOMEM;
	}

	ent = debugfs_create_file("cc_profiler_list", 0400, dev->dbg_root, dev,
				       &cc_profiler_list_fops);
	if (!ent)
		goto err_out;

	ent = debugfs_create_file("cc_profiler", 0600, dev->dbg_root, dev,
				       &cc_profiler_fops);
	if (!ent)
		goto err_out;

	ent = debugfs_create_file("tlp", 0600, dev->dbg_root, dev,
				       &tlp_fops);
	if (!ent)
		goto err_out;

	ent = debugfs_create_file("delay_ack", 0600, dev->dbg_root, dev,
				       &dack_fops);
	if (!ent)
		goto err_out;

	ent = debugfs_create_file("cap", 0400, dev->dbg_root, dev,
				       &cap_fops);
	if (!ent)
		goto err_out;

	ent = debugfs_create_file("mtte_usage", 0400, dev->dbg_root, dev,
				       &mtte_usage_fops);
	if (!ent)
		goto err_out;

	return 0;

err_out:
	debugfs_remove_recursive(dev->dbg_root);

	return -ENOMEM;
}

void erdma_debugfs_files_destroy(struct erdma_dev *dev)
{
	if (erdma_debugfs_root)
		debugfs_remove_recursive(dev->dbg_root);
}

void erdma_debugfs_register(void)
{
	erdma_debugfs_root = debugfs_create_dir("erdma", NULL);

	if (IS_ERR_OR_NULL(erdma_debugfs_root))
		erdma_debugfs_root = NULL;
}

void erdma_debugfs_unregister(void)
{
	debugfs_remove(erdma_debugfs_root);
}
