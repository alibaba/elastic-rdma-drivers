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

static ssize_t cap_read(struct file *filp, char __user *buf, size_t count,
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

	ret = snprintf(cbuf, sizeof(cbuf), "cap 0x%lx\next_cap 0x%x\n",
		       dev->attrs.cap_flags, resp.cap_mask);

	return simple_read_from_buffer(buf, count, pos, cbuf, ret);
}

static const struct file_operations cap_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = cap_read,
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

	ent = debugfs_create_file("delay_ack", 0600, dev->dbg_root, dev,
				       &dack_fops);
	if (!ent)
		goto err_out;

	ent = debugfs_create_file("cap", 0400, dev->dbg_root, dev,
				       &cap_fops);
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
