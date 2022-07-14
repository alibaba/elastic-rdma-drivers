// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB

/* Authors: Cheng Xu <chengyou@linux.alibaba.com> */
/* Copyright (c) 2020-2022, Alibaba Group. */

#include <linux/cdev.h>
#include <linux/sched.h>

#include "erdma_ioctl.h"
#include "erdma_verbs.h"
#ifdef HAVE_HEADER_LINUX_SCHED_TASK
#include <linux/sched/task.h>
#endif
#include <linux/mm.h>
#include <rdma/ib_umem.h>

static struct class *erdma_chrdev_class;
static struct cdev erdma_cdev;
static struct device *erdma_chrdev;
static dev_t erdma_char_dev;

#define ERDMA_CHRDEV_NAME "erdma"

static int erdma_ioctl_conf_cmd(struct erdma_dev *edev,
				struct erdma_ioctl_msg *msg)
{
	int ret = 0;

	if (msg->in.opcode == ERDMA_CONFIG_TYPE_CC) {
		if (msg->in.config_req.is_set)
			edev->attrs.cc = msg->in.config_req.value;
		else
			msg->out.config_resp.value = edev->attrs.cc;
	} else if (msg->in.opcode == ERDMA_CONFIG_TYPE_LOGLEVEL) {
		if (msg->in.config_req.is_set)
			dprint_mask = msg->in.config_req.value;
		else
			msg->out.config_resp.value = dprint_mask;
	}

	msg->out.length = 4;
	return ret;
}

static void fill_eq_info(struct erdma_eq_info *info, struct erdma_eq *eq)
{
	info->event_cnt = atomic64_read(&eq->event_num);
	info->notify_cnt = atomic64_read(&eq->notify_num);
	info->depth = eq->depth;
	info->ci = eq->ci;
	info->qbuf_dma = eq->qbuf_dma_addr;
	info->qbuf_va = (u64)eq->qbuf;
}

static void show_cep_info(struct erdma_dev *edev)
{
	u64 num_cep = atomic_read(&edev->num_cep);
	struct list_head *pos, *tmp;

	pr_info("%s: %llu CEPs\n", edev->ibdev.name, num_cep);

	if (!num_cep)
		return;

	pr_info("%-20s%-6s%-6s%-7s%-3s%-3s%-4s%-21s%-9s\n", "CEP", "State",
		"Ref's", "QP-ID", "LQ", "LC", "U", "Sock", "CM-ID");

	list_for_each_safe(pos, tmp, &edev->cep_list) {
		struct erdma_cep *cep = list_entry(pos, struct erdma_cep, devq);

		pr_info("0x%-18p%-6d%-6d%-7d%-3s%-3s%-4d0x%-18p 0x%-16p\n", cep,
			cep->state, kref_read(&cep->ref),
			cep->qp ? QP_ID(cep->qp) : -1,
			list_empty(&cep->listenq) ? "n" : "y",
			cep->listen_cep ? "y" : "n", cep->in_use, cep->sock,
			cep->cm_id);
	}
}

static int show_cq_info(struct erdma_dev *dev, u32 cqn,
			struct erdma_ioctl_msg *msg)
{
	struct erdma_cq_info *info = &msg->out.cq_info;
#ifdef HAVE_RDMA_RESTRACK_ENTRY_USER
	struct rdma_restrack_entry *res;
#endif
	struct erdma_cq *cq;

	cq = find_cq_by_cqn(dev, cqn);
	if (!cq)
		return -EINVAL;

	info->cqn = cq->cqn;
	info->depth = cq->depth;
	info->assoc_eqn = cq->assoc_eqn;

#ifdef HAVE_RDMA_RESTRACK_ENTRY_USER
	res = &cq->ibcq.res;
	info->is_user = !rdma_is_kernel_res(res);
#else
	info->is_user = cq->user;
#endif

	if (info->is_user) {

	}

#if 0
	pr_info("cqn:%u, hw_reported_cnt:%llx, sw_reported_cnt:%llx.\n", cqn,
		atomic64_read(&cq->hw_reported_cnt),
		atomic64_read(&cq->sw_reported_cnt));

	pr_info("last pi:%x\n", cq->last_pi);
#endif
	return 0;
}

static int erdma_ioctl_ver_cmd(struct erdma_dev *edev,
			       struct erdma_ioctl_msg *msg)
{
	msg->out.version =
		ERDMA_MAJOR_VER << 16 | ERDMA_MEDIUM_VER << 8 | ERDMA_MINOR_VER;

	return 0;
}

static int erdma_ioctl_info_cmd(struct erdma_dev *edev,
				struct erdma_ioctl_msg *msg)
{
	int ret = 0;
	struct erdma_qp *qp;
	struct erdma_qp_info *qp_info;
#ifdef HAVE_RDMA_RESTRACK_ENTRY_USER
	struct rdma_restrack_entry *res;
#endif
	int count = 0;
	struct erdma_mem *mtt;
	int i;
#ifdef HAVE_XARRAY
	unsigned long index;
#else
	void *entry;
	int index;
#endif

	switch (msg->in.opcode) {
	case ERDMA_INFO_TYPE_QP:
		qp = find_qp_by_qpn(edev, msg->in.info_req.qn);
		if (!qp)
			return -EINVAL;
		erdma_qp_get(qp);

		qp_info = &msg->out.qp_info;

		qp_info->qpn = qp->ibqp.qp_num;
		qp_info->qp_state = qp->attrs.state;
		qp_info->ref_cnt = kref_read(&qp->ref);
		qp_info->qtype = qp->attrs.qp_type;
		qp_info->sq_depth = qp->attrs.sq_size;
		qp_info->rq_depth = qp->attrs.rq_size;
		qp_info->cookie = qp->attrs.remote_cookie;
		qp_info->cc = qp->attrs.cc;
		qp_info->assoc_scqn = qp->scq->cqn;
		qp_info->assoc_rcqn = qp->rcq->cqn;

		if (qp->cep && qp->cep->cm_id) {
			struct erdma_cep *cep = qp->cep;
			struct iw_cm_id *id = cep->cm_id;
			struct sockaddr_storage	remote_addr;
			struct sockaddr_storage	local_addr;

			qp_info->sip = ntohl(to_sockaddr_in(id->local_addr).sin_addr.s_addr);
			qp_info->dip = ntohl(to_sockaddr_in(id->remote_addr).sin_addr.s_addr);
			qp_info->sport = ntohs(to_sockaddr_in(id->local_addr).sin_port);
			qp_info->dport = ntohs(to_sockaddr_in(id->remote_addr).sin_port);

			if (cep->sock) {
				getname_local(cep->sock, &local_addr);
				getname_peer(cep->sock, &remote_addr);
				qp_info->origin_sport = ntohs(to_sockaddr_in(local_addr).sin_port);
				qp_info->sip = ntohl(to_sockaddr_in(local_addr).sin_addr.s_addr);
			}
		}

#ifdef HAVE_RDMA_RESTRACK_ENTRY_USER
		res = &qp->ibqp.res;
		qp_info->is_user = !rdma_is_kernel_res(res);
		if (qp_info->is_user) {
			qp_info->pid = res->task->pid;
			get_task_comm(qp_info->buf, res->task);
#else
		if (qp->user) {
#endif
			mtt = &qp->user_qp.sq_mtt;
			qp_info->sq_mtt_type = mtt->mtt_type;
			qp_info->sq_mtt.page_size = mtt->page_size;
			qp_info->sq_mtt.page_offset = mtt->page_offset;
			qp_info->sq_mtt.page_cnt = mtt->page_cnt;
			qp_info->sq_mtt.mtt_nents = mtt->mtt_nents;
			qp_info->sq_mtt.va = mtt->va;
			qp_info->sq_mtt.len = mtt->len;
			for (i = 0; i < ERDMA_MAX_INLINE_MTT_ENTRIES; i++)
				qp_info->sq_mtt.mtt_entry[i] =
					mtt->mtt_entry[i];

			mtt = &qp->user_qp.rq_mtt;
			qp_info->rq_mtt_type = mtt->mtt_type;
			qp_info->rq_mtt.page_size = mtt->page_size;
			qp_info->rq_mtt.page_offset = mtt->page_offset;
			qp_info->rq_mtt.page_cnt = mtt->page_cnt;
			qp_info->rq_mtt.mtt_nents = mtt->mtt_nents;
			qp_info->rq_mtt.va = mtt->va;
			qp_info->rq_mtt.len = mtt->len;
			for (i = 0; i < ERDMA_MAX_INLINE_MTT_ENTRIES; i++)
				qp_info->rq_mtt.mtt_entry[i] =
					mtt->mtt_entry[i];
		}

		erdma_qp_put(qp);

		break;
	case ERDMA_INFO_TYPE_ALLOCED_QP:
#ifdef HAVE_XARRAY
		xa_for_each_start(&edev->qp_xa, index, qp, msg->in.info_req.qn) {
#else
		idr_for_each_entry(&edev->qp_idr, entry, index) {
			if (index < msg->in.info_req.qn)
				continue;
#endif
			msg->out.allocted_qpn[count++] = index;
			if (count == msg->in.info_req.max_result_cnt)
				break;
		}
		msg->out.length = count * 4;
		break;
	case ERDMA_INFO_TYPE_EQ:
		msg->out.eq_info[0].ready = 1;
		msg->out.eq_info[0].eqn = 0;
		fill_eq_info(&msg->out.eq_info[0], &edev->aeq);

		msg->out.eq_info[1].ready = 1;
		msg->out.eq_info[1].eqn = 1;
		fill_eq_info(&msg->out.eq_info[1], &edev->cmdq.eq);

		for (i = 0; i < 31; i++) {
			msg->out.eq_info[i + 2].ready = edev->ceqs[i].ready;
			msg->out.eq_info[i + 2].eqn = i + 2;
			fill_eq_info(&msg->out.eq_info[i + 2],
				     &edev->ceqs[i].eq);
		}
		break;
	case ERDMA_INFO_TYPE_CEP:
		show_cep_info(edev);
		break;
	case ERDMA_INFO_TYPE_CQ:
		ret = show_cq_info(edev, msg->in.info_req.qn, msg);
		break;
	default:
		pr_info("unknown opcode:%u\n", msg->in.opcode);
		return -EINVAL;
	}

	return ret;
}

int erdma_ioctl_stat_cmd(struct erdma_dev *edev, struct erdma_ioctl_msg *msg)
{
	__u64 *stats_data;

	switch (msg->in.opcode) {
	case ERDMA_STAT_TYPE_QP:
	case ERDMA_STAT_TYPE_CQ:
		break;
	case ERDMA_STAT_TYPE_DEV:
		stats_data = (__u64 *)msg->out.data;
		stats_data[0] = erdma_reg_read64(
			edev, ERDMA_REGS_STATS_TSO_IN_PKTS_REG);
		stats_data[1] = erdma_reg_read64(
			edev, ERDMA_REGS_STATS_TSO_OUT_PKTS_REG);
		stats_data[2] = erdma_reg_read64(
			edev, ERDMA_REGS_STATS_TSO_OUT_BYTES_REG);
		stats_data[3] = erdma_reg_read64(
			edev, ERDMA_REGS_STATS_TX_DROP_PKTS_REG);
		stats_data[4] = erdma_reg_read64(
			edev, ERDMA_REGS_STATS_TX_BPS_METER_DROP_PKTS_REG);
		stats_data[5] = erdma_reg_read64(
			edev, ERDMA_REGS_STATS_TX_PPS_METER_DROP_PKTS_REG);

		stats_data[6] =
			erdma_reg_read64(edev, ERDMA_REGS_STATS_RX_PKTS_REG);
		stats_data[7] =
			erdma_reg_read64(edev, ERDMA_REGS_STATS_RX_BYTES_REG);
		stats_data[8] = erdma_reg_read64(
			edev, ERDMA_REGS_STATS_RX_DROP_PKTS_REG);
		stats_data[9] = erdma_reg_read64(
			edev, ERDMA_REGS_STATS_RX_BPS_METER_DROP_PKTS_REG);
		stats_data[10] = erdma_reg_read64(
			edev, ERDMA_REGS_STATS_RX_PPS_METER_DROP_PKTS_REG);

		msg->out.length = 256;
		break;
	default:
		pr_err("unknown stat opcode %d.\n", msg->in.opcode);
		return -1;
	}

	return 0;
}

int erdma_ioctl_dump_cmd(struct erdma_dev *edev, struct erdma_ioctl_msg *msg)
{
	u32 qe_idx = msg->in.dump_req.qe_idx;
	u32 qn = msg->in.dump_req.qn;
	struct erdma_qp *qp;
	struct erdma_cq *cq;
	struct erdma_eq *eq;
	int ret = 0;
	u64 address;
	u32 wqe_idx;

	switch (msg->in.opcode) {
	case ERDMA_DUMP_TYPE_SQE:

		/* CMDQ-SQ */
		if (qn == 0) {
			wqe_idx = qe_idx & (edev->cmdq.sq.depth - 1);
			memcpy(msg->out.data,
			       edev->cmdq.sq.qbuf + (wqe_idx << SQEBB_SHIFT),
			       SQEBB_SIZE);
		} else {
			qp = find_qp_by_qpn(edev, qn);
			if (!qp)
				return -EINVAL;
			erdma_qp_get(qp);

#ifdef HAVE_RDMA_RESTRACK_ENTRY_USER
			if (!rdma_is_kernel_res(&qp->ibqp.res)) {
				address = qp->user_qp.sq_mtt.umem->address;
				wqe_idx = qe_idx & (qp->attrs.sq_size - 1);
				address += wqe_idx << SQEBB_SHIFT;
				ret = access_process_vm(qp->ibqp.res.task,
							address, msg->out.data,
							SQEBB_SIZE, FOLL_FORCE);
				if (ret != SQEBB_SIZE) {
					pr_info("access address with error (%d)\n",
						ret);
					erdma_qp_put(qp);
					return -EIO;
				}
			} else {
				wqe_idx = qe_idx & (qp->attrs.sq_size - 1);
				memcpy(msg->out.data,
				       qp->kern_qp.sq_buf +
					       (wqe_idx << SQEBB_SHIFT),
				       SQEBB_SIZE);
			}
#else
			ret = -ENOTSUPP;
#endif
			erdma_qp_put(qp);
		}
		msg->out.length = SQEBB_SIZE;
		break;
	case ERDMA_DUMP_TYPE_RQE:
		qp = find_qp_by_qpn(edev, qn);
		if (!qp)
			return -EINVAL;
		erdma_qp_get(qp);

#ifdef HAVE_RDMA_RESTRACK_ENTRY_USER
		if (!rdma_is_kernel_res(&qp->ibqp.res)) {
			address = qp->user_qp.rq_mtt.umem->address;
			wqe_idx = qe_idx & (qp->attrs.rq_size - 1);
			address += wqe_idx << RQE_SHIFT;
			ret = access_process_vm(qp->ibqp.res.task, address,
						msg->out.data, RQE_SIZE,
						FOLL_FORCE);
			if (ret != RQE_SIZE) {
				pr_info("access address with error (%d)\n",
					ret);
				erdma_qp_put(qp);
				return -EIO;
			}
		} else {
			wqe_idx = qe_idx & (qp->attrs.rq_size - 1);
			memcpy(msg->out.data,
			       qp->kern_qp.rq_buf + (wqe_idx << RQE_SHIFT),
			       RQE_SIZE);
		}
#else
		ret = -ENOTSUPP;
#endif
		erdma_qp_put(qp);
		msg->out.length = RQE_SIZE;
		break;
	case ERDMA_DUMP_TYPE_CQE:
		if (qn == 0) {
			/* CMDQ-CQ */
			wqe_idx = qe_idx & (edev->cmdq.cq.depth - 1);
			memcpy(msg->out.data,
			       edev->cmdq.cq.qbuf + (wqe_idx << CQE_SHIFT),
			       CQE_SIZE);
		} else {
			cq = find_cq_by_cqn(edev, qn);
			if (!cq)
				return -EINVAL;

#ifdef HAVE_RDMA_RESTRACK_ENTRY_USER
			if (!rdma_is_kernel_res(&cq->ibcq.res)) {
				address = cq->user_cq.qbuf_mtt.umem->address;
				wqe_idx = qe_idx & (cq->depth - 1);
				address += wqe_idx << CQE_SHIFT;
				ret = access_process_vm(cq->ibcq.res.task,
							address, msg->out.data,
							CQE_SIZE, FOLL_FORCE);
				if (ret != CQE_SIZE) {
					pr_info("access address with error (%d)\n",
						ret);
					return -EIO;
				}
			} else {
				wqe_idx = qe_idx & (cq->depth - 1);
				memcpy(msg->out.data,
				       cq->kern_cq.qbuf +
					       (wqe_idx << CQE_SHIFT),
				       CQE_SIZE);
			}
#else
			ret = -ENOTSUPP;
#endif
		}
		msg->out.length = CQE_SIZE;
		break;

	case ERDMA_DUMP_TYPE_EQE:
		/* 0: AEQ, 1: CMD-EQ, 2 - 33: CEQ */
		if (qn == 0) { /* AEQ */
			eq = &edev->aeq;
		} else if (qn == 1) {
			eq = &edev->cmdq.eq;
		} else if (qn > 1 && qn <= 33) {
			if (edev->ceqs[qn - 2].ready == 0)
				return -EINVAL;
			eq = &edev->ceqs[qn - 2].eq;
		} else {
			return -EINVAL;
		}

		wqe_idx = qe_idx & (eq->depth - 1);
		memcpy(msg->out.data, eq->qbuf + (wqe_idx << EQE_SHIFT),
		       EQE_SIZE);
		msg->out.length = EQE_SIZE;
	default:
		break;
	}

	return ret;
}

typedef int (*ioctl_proc)(struct erdma_dev *, struct erdma_ioctl_msg *);

static const ioctl_proc erdma_ioctl_proc_table[EADM_CMD_MAX] = {
	[EADM_DUMP_CMD] = erdma_ioctl_dump_cmd,
	[EADM_INFO_CMD] = erdma_ioctl_info_cmd,
	[EADM_CONF_CMD] = erdma_ioctl_conf_cmd,
	[EADM_STAT_CMD] = erdma_ioctl_stat_cmd,
	[EADM_VER_CMD] = erdma_ioctl_ver_cmd,
};

long do_ioctl(unsigned int cmd, unsigned long arg)
{
	struct erdma_dev *edev = NULL;
	struct ib_device *ibdev = NULL;
	struct erdma_ioctl_msg *msg;
	int ret = 0, bypass_dev = 0;
	int command;

	msg = kzalloc(sizeof(*msg), GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	ret = copy_from_user(msg, (const void *)arg,
			     sizeof(struct erdma_ioctl_msg));
	if (ret) {
		kfree(msg);
		return -EINVAL;
	}

	if (_IOC_TYPE(cmd) != ERDMA_IOC_MAGIC ||
	    _IOC_NR(cmd) > ERDMA_IOC_MAXNR) {
		kfree(msg);
		return -EINVAL;
	}

	command = _IOC_NR(cmd);
	if (command >= EADM_CMD_MAX || !erdma_ioctl_proc_table[command]) {
		ret = -EINVAL;
		goto out;
	}

	/* 允许某些命令在没有ibdev的情况下执行 */
	if (command == EADM_VER_CMD)
		bypass_dev = 1;

	if (bypass_dev)
		goto exec_cmd;

	ibdev = ib_device_get_by_name(msg->in.ibdev_name, RDMA_DRIVER_ERDMA);
	if (ibdev) {
		edev = to_edev(ibdev);
	} else {
		kfree(msg);
		return -ENODEV;
	}

exec_cmd:
	msg->out.status = erdma_ioctl_proc_table[command](edev, msg);

	ret = copy_to_user((void *)arg, (const void *)msg,
			   sizeof(struct erdma_ioctl_msg));

out:
	if (!bypass_dev)
		ib_device_put(ibdev);

	kfree(msg);
	return ret;
}

long chardev_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	return do_ioctl(cmd, arg);
}

static char *erdma_chrdev_devnode(struct device *dev, umode_t *mode)
{
	if (mode)
		*mode = 0666;
	return kasprintf(GFP_KERNEL, "%s", dev_name(dev));
}

static int chardev_open(struct inode *inode, struct file *file)
{
	return 0;
}

static ssize_t chardev_read(struct file *file, char __user *buf, size_t size,
			    loff_t *ppos)
{
	return 0;
}

static int chardev_close(struct inode *inode, struct file *filp)
{
	return 0;
}

static const struct file_operations chardev_fops = {
	.owner = THIS_MODULE,
	.open = chardev_open,
	.release = chardev_close,
	.read = chardev_read,
	.unlocked_ioctl = chardev_ioctl
};

void erdma_chrdev_destroy(void)
{
	device_destroy(erdma_chrdev_class, erdma_char_dev);
	cdev_del(&erdma_cdev);
	class_destroy(erdma_chrdev_class);

	unregister_chrdev_region(erdma_char_dev, 1);
}

int erdma_chrdev_init(void)
{
	int ret;

	ret = alloc_chrdev_region(&erdma_char_dev, 0, 1, ERDMA_CHRDEV_NAME);
	if (ret) {
		pr_err("alloc chrdev failed.\n");
		return ret;
	}

	erdma_chrdev_class = class_create(THIS_MODULE, ERDMA_CHRDEV_NAME);
	if (IS_ERR(erdma_chrdev_class)) {
		ret = PTR_ERR(erdma_chrdev_class);
		pr_err("create class failed.\n");
		goto free_chrdev_region;
	}

	erdma_chrdev_class->devnode = erdma_chrdev_devnode;

	cdev_init(&erdma_cdev, &chardev_fops);
	erdma_cdev.owner = THIS_MODULE;
	ret = cdev_add(&erdma_cdev, erdma_char_dev, 1);
	if (ret) {
		pr_err("cdev add failed. ret = %d\n", ret);
		goto destroy_class;
	}

	erdma_chrdev = device_create(erdma_chrdev_class, NULL, erdma_char_dev,
				     NULL, ERDMA_CHRDEV_NAME);
	if (IS_ERR(erdma_chrdev)) {
		pr_err("create_device failed.\n");
		goto delete_cdev;
	}

	return 0;

delete_cdev:
	cdev_del(&erdma_cdev);

destroy_class:
	class_destroy(erdma_chrdev_class);

free_chrdev_region:
	unregister_chrdev_region(erdma_char_dev, 1);

	return ret;
}
