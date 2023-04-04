// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

/* Authors: Cheng Xu <chengyou@linux.alibaba.com> */
/*          Kai Shen <kaishen@linux.alibaba.com> */
/* Copyright (c) 2020-2022, Alibaba Group. */

#include <linux/cdev.h>
#include <linux/etherdevice.h>
#include <linux/module.h>
#include <net/addrconf.h>

#include "erdma.h"
#include "erdma-abi.h"
#include "erdma_cm.h"
#include "erdma_verbs.h"

MODULE_AUTHOR("Cheng Xu <chengyou@linux.alibaba.com>");
MODULE_AUTHOR("Kai Shen <kaishen@linux.alibaba.com>");
MODULE_DESCRIPTION("Alibaba elasticRDMA adapter driver");
MODULE_LICENSE("Dual BSD/GPL");

__u32 dprint_mask;
module_param(dprint_mask, uint, 0644);
MODULE_PARM_DESC(dprint_mask, "debug information print level");

bool compat_mode;
module_param(compat_mode, bool, 0444);
MODULE_PARM_DESC(compat_mode, "compat mode support");

bool rand_qpn;
module_param(rand_qpn, bool, 0444);
MODULE_PARM_DESC(rand_qpn, "randomized qpn");

static unsigned int vector_num = ERDMA_NUM_MSIX_VEC;
module_param(vector_num, uint, 0444);
MODULE_PARM_DESC(vector_num, "number of compeletion vectors");

u16 reserve_ports_base = 0x7790;
module_param(reserve_ports_base, ushort, 0444);
MODULE_PARM_DESC(reserve_ports_base, "ports reserved in RoCE mode");

#ifndef HAVE_IB_DEVICE_GET_BY_NAME
static LIST_HEAD(dev_list);
static DECLARE_RWSEM(devices_rwsem);

static void erdma_add_dev_to_list(struct erdma_dev *dev)
{
	down_read(&devices_rwsem);
	list_add_tail(&dev->dev_list, &dev_list);
	up_read(&devices_rwsem);
}

static void erdma_remove_dev_from_list(struct erdma_dev *dev)
{
	down_read(&devices_rwsem);
	list_del(&dev->dev_list);
	up_read(&devices_rwsem);
}

struct ib_device *ib_device_get_by_name(const char *name,
					unsigned int driver_id)
{
	struct ib_device *ibdev = NULL;
	struct erdma_dev *edev;

	down_read(&devices_rwsem);

	list_for_each_entry(edev, &dev_list, dev_list) {
		if (!strcmp(name, edev->ibdev.name)) {
			ibdev = &edev->ibdev;
			break;
		}
	}

	up_read(&devices_rwsem);

	return ibdev;
}

void ib_device_put(struct ib_device *device)
{
}

#endif

static int erdma_netdev_event(struct notifier_block *nb, unsigned long event,
			      void *arg)
{
	struct net_device *netdev = netdev_notifier_info_to_dev(arg);
	struct erdma_dev *dev = container_of(nb, struct erdma_dev, netdev_nb);

	dprint(DBG_CTRL, " netdev:%s,ns:%p: Event %lu to erdma_dev %p\n",
	       netdev->name, dev_net(netdev), event, dev);

	if (dev->netdev == NULL || dev->netdev != netdev)
		goto done;

	switch (event) {
	case NETDEV_UP:
		dev->state = IB_PORT_ACTIVE;
		erdma_port_event(dev, IB_EVENT_PORT_ACTIVE);
		break;
	case NETDEV_DOWN:
		dev->state = IB_PORT_DOWN;
		erdma_port_event(dev, IB_EVENT_PORT_ERR);
		break;
	case NETDEV_CHANGEMTU:
		if (dev->mtu != netdev->mtu) {
			erdma_set_mtu(dev, netdev->mtu);
			dev->mtu = netdev->mtu;
		}
		break;
	case NETDEV_REGISTER:
	case NETDEV_UNREGISTER:
	case NETDEV_CHANGEADDR:
	case NETDEV_GOING_DOWN:
	case NETDEV_CHANGE:
	default:
		break;
	}

done:
	return NOTIFY_OK;
}

static int erdma_enum_and_get_netdev(struct erdma_dev *dev)
{
	struct net_device *netdev;
	int ret = -ENODEV;

	/* Already binded to a net_device, so we skip. */
	if (dev->netdev)
		return 0;

	rtnl_lock();
	for_each_netdev(&init_net, netdev) {
		/*
		 * In erdma, the paired netdev and ibdev should have the same
		 * MAC address. erdma can get the value from its PCIe bar
		 * registers. Since erdma can not get the paired netdev
		 * reference directly, we do a traverse here to get the paired
		 * netdev.
		 */
		if (ether_addr_equal_unaligned(netdev->perm_addr,
					       dev->attrs.peer_addr)) {
#ifdef HAVE_IB_DEVICE_SET_NETDEV
			ret = ib_device_set_netdev(&dev->ibdev, netdev, 1);
			if (ret) {
				rtnl_unlock();
				ibdev_warn(&dev->ibdev,
					   "failed (%d) to link netdev", ret);
				return ret;
			}
#else
			/* Already get the assoc netdev. */
			ret = 0;
#endif
			dev->netdev = netdev;
			break;
		}
	}

	rtnl_unlock();

	return ret;
}

static int erdma_device_register(struct erdma_dev *dev)
{
	struct ib_device *ibdev = &dev->ibdev;
	int ret;

	memset(ibdev->name, 0, IB_DEVICE_NAME_MAX);
	/*
	 * In Ali ECS environment, ENI's mac address is unique in VPC.
	 * So, generating the ibdev's name from mac address of the binded
	 * netdev.
	 */
	ret = snprintf(ibdev->name, IB_DEVICE_NAME_MAX, "%s_%.2x%.2x%.2x",
		       DRV_MODULE_NAME, dev->attrs.peer_addr[3],
		       dev->attrs.peer_addr[4], dev->attrs.peer_addr[5]);
	if (ret < 0)
		return ret;

	ret = erdma_enum_and_get_netdev(dev);
	if (ret)
		return -EPROBE_DEFER;

	dev->mtu = dev->netdev->mtu;
	erdma_set_mtu(dev, dev->mtu);
	addrconf_addr_eui48((u8 *)&ibdev->node_guid, dev->netdev->dev_addr);

	ret = erdma_set_retrans_num(dev, ERDMA_DEFAULT_RETRANS_NUM);
	if (ret)
		dev->attrs.retrans_num = 0;

#ifdef HAVE_IB_REGISTER_DEVICE_DMA_DEVICE_PARAM
	ret = ib_register_device(ibdev, ibdev->name, &dev->pdev->dev);
#elif defined(HAVE_IB_REGISTER_DEVICE_TWO_PARAMS)
	ret = ib_register_device(ibdev, ibdev->name);
#elif defined(HAVE_IB_REGISTER_DEVICE_NAME_PARAM)
	ret = ib_register_device(ibdev, ibdev->name, NULL);
#else
	ret = ib_register_device(ibdev, NULL);
#endif
	if (ret) {
		dev_err(&dev->pdev->dev,
			"ib_register_device(%s) failed: ret = %d\n",
			ibdev->name, ret);
		return ret;
	}

	dev->netdev_nb.notifier_call = erdma_netdev_event;
#ifndef HAVE_NETDEV_NOTIFIER_RH
	ret = register_netdevice_notifier(&dev->netdev_nb);
#else
	ret = register_netdevice_notifier_rh(&dev->netdev_nb);
#endif
	if (ret) {
		ibdev_err(&dev->ibdev, "failed to register notifier.\n");
		ib_unregister_device(ibdev);
		return ret;
	}

	dprint(DBG_DM,
	       " Registered '%s' for interface '%s',HWaddr=%02x.%02x.%02x.%02x.%02x.%02x\n",
	       ibdev->name, dev->netdev->name, *(__u8 *)dev->netdev->dev_addr,
	       *((__u8 *)dev->netdev->dev_addr + 1),
	       *((__u8 *)dev->netdev->dev_addr + 2),
	       *((__u8 *)dev->netdev->dev_addr + 3),
	       *((__u8 *)dev->netdev->dev_addr + 4),
	       *((__u8 *)dev->netdev->dev_addr + 5));

#ifndef HAVE_IB_DEVICE_GET_BY_NAME
	erdma_add_dev_to_list(dev);
#endif
	return 0;
}

static irqreturn_t erdma_comm_irq_handler(int irq, void *data)
{
	struct erdma_dev *dev = data;

	erdma_cmdq_completion_handler(&dev->cmdq);
	erdma_aeq_event_handler(dev);

	return IRQ_HANDLED;
}

static void erdma_dwqe_resource_init(struct erdma_dev *dev)
{
	int total_pages, type0, type1;

	dev->attrs.grp_num = erdma_reg_read32(dev, ERDMA_REGS_GRP_NUM_REG);

	if (dev->attrs.grp_num < 4)
		dev->attrs.disable_dwqe = true;
	else
		dev->attrs.disable_dwqe = false;

	/* One page contains 4 goups. */
	total_pages = dev->attrs.grp_num * 4;

	if (dev->attrs.grp_num >= ERDMA_DWQE_MAX_GRP_CNT) {
		dev->attrs.grp_num = ERDMA_DWQE_MAX_GRP_CNT;
		type0 = ERDMA_DWQE_TYPE0_CNT;
		type1 = ERDMA_DWQE_TYPE1_CNT / ERDMA_DWQE_TYPE1_CNT_PER_PAGE;
	} else {
		type1 = total_pages / 3;
		type0 = total_pages - type1 - 1;
	}

	dev->attrs.dwqe_pages = type0;
	dev->attrs.dwqe_entries = type1 * ERDMA_DWQE_TYPE1_CNT_PER_PAGE;

	dev_info(
		&dev->pdev->dev,
		"grp_num:%d, total pages:%d, type0:%d, type1:%d, type1_db_cnt:%d\n",
		dev->attrs.grp_num, total_pages, type0, type1, type1 * 16);
}

static int erdma_request_vectors(struct erdma_dev *dev)
{
	int expect_irq_num = min(num_possible_cpus() + 1, vector_num);
#ifdef HAVE_NO_PCI_IRQ_NEW_API
	int i;
	struct msix_entry *msix_entry =
		kmalloc_array(expect_irq_num, sizeof(*msix_entry), GFP_KERNEL);
	if (!msix_entry)
		return -ENOMEM;

	for (i = 0; i < expect_irq_num; ++i)
		msix_entry[i].entry = i;
	dev->attrs.irq_num =
		pci_enable_msix_range(dev->pdev, msix_entry, 1, expect_irq_num);
#else
	dev->attrs.irq_num = pci_alloc_irq_vectors(dev->pdev, 1, expect_irq_num,
						   PCI_IRQ_MSIX);
#endif
	if (dev->attrs.irq_num <= 0) {
		dev_err(&dev->pdev->dev, "request irq vectors failed(%d)\n",
			dev->attrs.irq_num);
#ifdef HAVE_NO_PCI_IRQ_NEW_API
		kfree(msix_entry);
#endif
		return -ENOSPC;
	}

#ifdef HAVE_NO_PCI_IRQ_NEW_API
	dev->comm_irq.msix_vector = msix_entry[0].vector;
	for (i = 1; i < dev->attrs.irq_num; i++)
		dev->ceqs[i - 1].irq.msix_vector = msix_entry[i].vector;
	kfree(msix_entry);
#endif

	return 0;
}

static int erdma_comm_irq_init(struct erdma_dev *dev)
{
	snprintf(dev->comm_irq.name, ERDMA_IRQNAME_SIZE, "erdma-common@pci:%s",
		 pci_name(dev->pdev));
	dev->comm_irq.msix_vector =
		pci_irq_vector(dev->pdev, ERDMA_MSIX_VECTOR_CMDQ);

	cpumask_set_cpu(cpumask_first(cpumask_of_pcibus(dev->pdev->bus)),
			&dev->comm_irq.affinity_hint_mask);
	irq_set_affinity_hint(dev->comm_irq.msix_vector,
			      &dev->comm_irq.affinity_hint_mask);

	return request_irq(dev->comm_irq.msix_vector, erdma_comm_irq_handler, 0,
			   dev->comm_irq.name, dev);
}

static void erdma_comm_irq_uninit(struct erdma_dev *dev)
{
	irq_set_affinity_hint(dev->comm_irq.msix_vector, NULL);
	free_irq(dev->comm_irq.msix_vector, dev);
}

static int erdma_hw_resp_pool_init(struct erdma_dev *dev)
{
	dev->resp_pool =
		dma_pool_create("erdma_resp_pool", &dev->pdev->dev,
				ERDMA_HW_RESP_SIZE, ERDMA_HW_RESP_SIZE, 0);
	if (!dev->resp_pool)
		return -ENOMEM;

	return 0;
}

static void erdma_hw_resp_pool_destroy(struct erdma_dev *dev)
{
	dma_pool_destroy(dev->resp_pool);
}

static int erdma_device_init(struct erdma_dev *dev, struct pci_dev *pdev)
{
	int ret;

	erdma_dwqe_resource_init(dev);
	ret = erdma_hw_resp_pool_init(dev);
	if (ret)
		return ret;

	ret = dma_set_mask_and_coherent(&pdev->dev,
					DMA_BIT_MASK(ERDMA_PCI_WIDTH));
	if (ret) {
		erdma_hw_resp_pool_destroy(dev);
		return ret;
	}

	dma_set_max_seg_size(&pdev->dev, UINT_MAX);

	return 0;
}

static void erdma_device_uninit(struct erdma_dev *dev)
{
	erdma_hw_resp_pool_destroy(dev);
}

static int erdma_wait_hw_init_done(struct erdma_dev *dev)
{
	int i;

	erdma_reg_write32(dev, ERDMA_REGS_DEV_CTRL_REG,
			  FIELD_PREP(ERDMA_REG_DEV_CTRL_INIT_MASK, 1));

	for (i = 0; i < ERDMA_WAIT_DEV_DONE_CNT; i++) {
		if (erdma_reg_read32_filed(dev, ERDMA_REGS_DEV_ST_REG,
					   ERDMA_REG_DEV_ST_INIT_DONE_MASK))
			break;

		msleep(ERDMA_REG_ACCESS_WAIT_MS);
	}

	if (i == ERDMA_WAIT_DEV_DONE_CNT) {
		dev_err(&dev->pdev->dev, "wait init done failed.\n");
		return -ETIMEDOUT;
	}

	return 0;
}

static void erdma_hw_stop(struct erdma_dev *dev)
{
	u32 ctrl = FIELD_PREP(ERDMA_REG_DEV_CTRL_RESET_MASK, 1);

	erdma_reg_write32(dev, ERDMA_REGS_DEV_CTRL_REG, ctrl);
}

static const struct pci_device_id erdma_pci_tbl[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_ALIBABA, 0x107f) },
	{}
};

static int erdma_probe_dev(struct pci_dev *pdev)
{
	struct erdma_dev *dev;
	int bars, err;
	u32 version;

	err = pci_enable_device(pdev);
	if (err) {
		dev_err(&pdev->dev, "pci_enable_device failed(%d)\n", err);
		return err;
	}

	pci_set_master(pdev);

#ifdef HAVE_SAFE_IB_ALLOC_DEVICE
	dev = ib_alloc_device(erdma_dev, ibdev);
#else
	dev = (struct erdma_dev *)ib_alloc_device(sizeof(*dev));
#endif
	if (!dev) {
		dev_err(&pdev->dev, "ib_alloc_device failed\n");
		err = -ENOMEM;
		goto err_disable_device;
	}

	pci_set_drvdata(pdev, dev);
	dev->pdev = pdev;
	dev->attrs.numa_node = dev_to_node(&pdev->dev);

	bars = pci_select_bars(pdev, IORESOURCE_MEM);
	err = pci_request_selected_regions(pdev, bars, DRV_MODULE_NAME);
	if (bars != ERDMA_BAR_MASK || err) {
		err = err ? err : -EINVAL;
		goto err_ib_device_release;
	}

	dev->func_bar_addr = pci_resource_start(pdev, ERDMA_FUNC_BAR);
	dev->func_bar_len = pci_resource_len(pdev, ERDMA_FUNC_BAR);

	dev->func_bar =
		devm_ioremap(&pdev->dev, dev->func_bar_addr, dev->func_bar_len);
	if (!dev->func_bar) {
		dev_err(&pdev->dev, "devm_ioremap failed.\n");
		err = -EFAULT;
		goto err_release_bars;
	}

	version = erdma_reg_read32(dev, ERDMA_REGS_VERSION_REG);
	if (version == 0) {
		/* we knows that it is a non-functional function. */
		err = -ENODEV;
		goto err_iounmap_func_bar;
	}

	err = erdma_device_init(dev, pdev);
	if (err)
		goto err_iounmap_func_bar;

	err = erdma_request_vectors(dev);
	if (err)
		goto err_uninit_device;

	err = erdma_comm_irq_init(dev);
	if (err)
		goto err_free_vectors;

	err = erdma_aeq_init(dev);
	if (err)
		goto err_uninit_comm_irq;

	err = erdma_cmdq_init(dev);
	if (err)
		goto err_uninit_aeq;

	err = erdma_wait_hw_init_done(dev);
	if (err)
		goto err_uninit_cmdq;

	err = erdma_ceqs_init(dev);
	if (err)
		goto err_stop_hw;

	msleep(500);

	erdma_finish_cmdq_init(dev);

	return 0;

err_stop_hw:
	erdma_hw_stop(dev);

err_uninit_cmdq:
	erdma_cmdq_destroy(dev);

err_uninit_aeq:
	erdma_aeq_destroy(dev);

err_uninit_comm_irq:
	erdma_comm_irq_uninit(dev);

err_free_vectors:
#ifdef HAVE_NO_PCI_IRQ_NEW_API
	pci_disable_msix(dev->pdev);
#else
	pci_free_irq_vectors(dev->pdev);
#endif

err_uninit_device:
	erdma_device_uninit(dev);

err_iounmap_func_bar:
	devm_iounmap(&pdev->dev, dev->func_bar);

err_release_bars:
	pci_release_selected_regions(pdev, bars);

err_ib_device_release:
	ib_dealloc_device(&dev->ibdev);

err_disable_device:
	pci_disable_device(pdev);

	return err;
}

static void erdma_remove_dev(struct pci_dev *pdev)
{
	struct erdma_dev *dev = pci_get_drvdata(pdev);

	erdma_ceqs_uninit(dev);
	erdma_hw_stop(dev);
	erdma_cmdq_destroy(dev);
	erdma_aeq_destroy(dev);
	erdma_comm_irq_uninit(dev);
#ifdef HAVE_NO_PCI_IRQ_NEW_API
	pci_disable_msix(dev->pdev);
#else
	pci_free_irq_vectors(dev->pdev);
#endif
	erdma_device_uninit(dev);
	devm_iounmap(&pdev->dev, dev->func_bar);
	pci_release_selected_regions(pdev, ERDMA_BAR_MASK);
	ib_dealloc_device(&dev->ibdev);
	pci_disable_device(pdev);
}

static void erdma_stats_init(struct erdma_dev *dev)
{
	atomic64_t *s = (atomic64_t *)&dev->stats;
	int i;

	for (i = 0; i < sizeof(dev->stats) / sizeof(*s); i++, s++)
		atomic64_set(s, 0);
}

static int erdma_check_version(struct erdma_dev *dev)
{
	u8 fw_major = (dev->attrs.fw_version >> 16);
	u8 fw_medium = (dev->attrs.fw_version >> 8);

	return (fw_major != ERDMA_MAJOR_VER || fw_medium != ERDMA_MEDIUM_VER) ?
		       -1 :
			     0;
}

#define ERDMA_GET_CAP(name, cap) FIELD_GET(ERDMA_CMD_DEV_CAP_##name##_MASK, cap)

static int erdma_dev_attrs_init(struct erdma_dev *dev)
{
	int err;
	u64 req_hdr, cap0, cap1;

	erdma_cmdq_build_reqhdr(&req_hdr, CMDQ_SUBMOD_RDMA,
				CMDQ_OPCODE_QUERY_DEVICE);

	err = erdma_post_cmd_wait(&dev->cmdq, &req_hdr, sizeof(req_hdr), &cap0,
				  &cap1);
	if (err)
		return err;

	dev->attrs.max_cqe = 1 << ERDMA_GET_CAP(MAX_CQE, cap0);
	dev->attrs.max_mr_size = 1ULL << ERDMA_GET_CAP(MAX_MR_SIZE, cap0);
	dev->attrs.max_mw = 1 << ERDMA_GET_CAP(MAX_MW, cap1);
	dev->attrs.max_recv_wr = 1 << ERDMA_GET_CAP(MAX_RECV_WR, cap0);
	dev->attrs.local_dma_key = ERDMA_GET_CAP(DMA_LOCAL_KEY, cap1);
	dev->attrs.cc = ERDMA_GET_CAP(DEFAULT_CC, cap1);
	dev->attrs.max_qp = ERDMA_NQP_PER_QBLOCK * ERDMA_GET_CAP(QBLOCK, cap1);
	dev->attrs.max_mr = dev->attrs.max_qp << 1;
	dev->attrs.max_cq = dev->attrs.max_qp << 1;
	dev->attrs.flags = ERDMA_GET_CAP(FLAGS, cap0);

	dev->attrs.max_send_wr = ERDMA_MAX_SEND_WR;
	dev->attrs.max_ord = ERDMA_MAX_ORD;
	dev->attrs.max_ird = ERDMA_MAX_IRD;
	dev->attrs.max_send_sge = ERDMA_MAX_SEND_SGE;
	dev->attrs.max_recv_sge = ERDMA_MAX_RECV_SGE;
	dev->attrs.max_sge_rd = ERDMA_MAX_SGE_RD;
	dev->attrs.max_pd = ERDMA_MAX_PD;

	dev->res_cb[ERDMA_RES_TYPE_PD].max_cap = ERDMA_MAX_PD;
	dev->res_cb[ERDMA_RES_TYPE_STAG_IDX].max_cap = dev->attrs.max_mr;

	erdma_cmdq_build_reqhdr(&req_hdr, CMDQ_SUBMOD_COMMON,
				CMDQ_OPCODE_QUERY_FW_INFO);

	err = erdma_post_cmd_wait(&dev->cmdq, &req_hdr, sizeof(req_hdr), &cap0,
				  &cap1);
	if (!err)
		dev->attrs.fw_version =
			FIELD_GET(ERDMA_CMD_INFO0_FW_VER_MASK, cap0);

	return erdma_check_version(dev);
}

static int erdma_res_cb_init(struct erdma_dev *dev)
{
	int i, j;

	for (i = 0; i < ERDMA_RES_CNT; i++) {
		dev->res_cb[i].next_alloc_idx = 1;
		spin_lock_init(&dev->res_cb[i].lock);
		dev->res_cb[i].bitmap =
			kcalloc(BITS_TO_LONGS(dev->res_cb[i].max_cap),
				sizeof(unsigned long), GFP_KERNEL);
		if (!dev->res_cb[i].bitmap)
			goto err;
	}

	return 0;

err:
	for (j = 0; j < i; j++)
		kfree(dev->res_cb[j].bitmap);

	return -ENOMEM;
}

static void erdma_res_cb_free(struct erdma_dev *dev)
{
	int i;

	for (i = 0; i < ERDMA_RES_CNT; i++)
		kfree(dev->res_cb[i].bitmap);
}

#ifdef HAVE_IB_DEV_OPS
static const struct ib_device_ops erdma_device_ops = {
	.owner = THIS_MODULE,
	.driver_id = RDMA_DRIVER_ERDMA,
	.uverbs_abi_ver = ERDMA_ABI_VERSION,
#ifdef HAVE_SINGLE_HW_STATS
	.alloc_hw_stats = erdma_alloc_hw_stats,
#endif
#ifdef HAVE_SPLIT_STATS_ALLOC
	.alloc_hw_port_stats = erdma_alloc_hw_stats,
#endif
	.alloc_mr = erdma_ib_alloc_mr,
	.alloc_pd = erdma_alloc_pd,
	.alloc_ucontext = erdma_alloc_ucontext,
	.create_cq = erdma_create_cq,
#ifndef HAVE_QP_CORE_ALLOCATION
	.create_qp = erdma_kzalloc_qp,
#else
	.create_qp = erdma_create_qp,
#endif
	.dealloc_pd = erdma_dealloc_pd,
	.dealloc_ucontext = erdma_dealloc_ucontext,
	.dereg_mr = erdma_dereg_mr,
	.destroy_cq = erdma_destroy_cq,
	.destroy_qp = erdma_destroy_qp,
#ifdef HAVE_IWARP_OUTBOUND_QP_CREATE_FOR_SMC /* Only used in SMC. */
	.disassociate_ucontext = erdma_disassociate_ucontext,
#endif
	.get_dma_mr = erdma_get_dma_mr,
#if defined(HAVE_SINGLE_HW_STATS) || defined(HAVE_SPLIT_STATS_ALLOC)
	.get_hw_stats = erdma_get_hw_stats,
#endif
	.get_port_immutable = erdma_get_port_immutable,
	.iw_accept = erdma_accept,
	.iw_add_ref = erdma_qp_get_ref,
	.iw_connect = erdma_connect,
	.iw_create_listen = erdma_create_listen,
	.iw_destroy_listen = erdma_destroy_listen,
	.iw_get_qp = erdma_get_ibqp,
	.iw_reject = erdma_reject,
	.iw_rem_ref = erdma_qp_put_ref,
	.map_mr_sg = erdma_map_mr_sg,
	.mmap = erdma_mmap,
#ifdef HAVE_CORE_MMAP_XA
	.mmap_free = erdma_mmap_free,
#endif
	.modify_qp = erdma_modify_qp,
	.post_recv = erdma_post_recv,
	.post_send = erdma_post_send,
	.poll_cq = erdma_poll_cq,
	.query_device = erdma_query_device,
	.query_gid = erdma_query_gid,
	.query_port = erdma_query_port,
	.query_qp = erdma_query_qp,
	.req_notify_cq = erdma_req_notify_cq,
	.reg_user_mr = erdma_reg_user_mr,
	.get_netdev = erdma_get_netdev,
	.query_pkey = erdma_query_pkey,
	.modify_cq = erdma_modify_cq,

	INIT_RDMA_OBJ_SIZE(ib_cq, erdma_cq, ibcq),
	INIT_RDMA_OBJ_SIZE(ib_pd, erdma_pd, ibpd),
	INIT_RDMA_OBJ_SIZE(ib_ucontext, erdma_ucontext, ibucontext),
#ifdef HAVE_QP_CORE_ALLOCATION
	INIT_RDMA_OBJ_SIZE(ib_qp, erdma_qp, ibqp),
#endif
};

static const struct ib_device_ops erdma_compat_ops = {
	.get_link_layer = erdma_get_link_layer,
	.add_gid = erdma_add_gid,
	.del_gid = erdma_del_gid,
};

#else
static void erdma_ibverbs_init(struct ib_device *ibdev)
{
	ibdev->owner = THIS_MODULE;

#ifdef HAVE_DRIVER_ID
	ibdev->driver_id = RDMA_DRIVER_ERDMA;
#endif
	ibdev->uverbs_abi_ver = ERDMA_ABI_VERSION;

	if (compat_mode)
		ibdev->get_link_layer = erdma_get_link_layer;

	ibdev->query_device = erdma_query_device;
	ibdev->query_port = erdma_query_port;
	ibdev->get_port_immutable = erdma_get_port_immutable;
	ibdev->query_qp = erdma_query_qp;
	ibdev->query_pkey = erdma_query_pkey;
	ibdev->query_gid = erdma_query_gid;
	ibdev->alloc_ucontext = erdma_kzalloc_ucontext;
	ibdev->dealloc_ucontext = erdma_dealloc_ucontext;
	ibdev->mmap = erdma_mmap;
#ifdef HAVE_CORE_MMAP_XA
	ibdev->mmap_free = erdma_mmap_free,
#endif
	ibdev->alloc_pd = erdma_kzalloc_pd;
	ibdev->dealloc_pd = erdma_dealloc_pd;
	ibdev->create_qp = erdma_kzalloc_qp;
	ibdev->modify_qp = erdma_modify_qp;
	ibdev->destroy_qp = erdma_destroy_qp;
	ibdev->create_cq = erdma_kzalloc_cq;
	ibdev->destroy_cq = erdma_destroy_cq;
	ibdev->poll_cq = erdma_poll_cq;
	ibdev->get_dma_mr = erdma_get_dma_mr;
	ibdev->reg_user_mr = erdma_reg_user_mr;
	ibdev->dereg_mr = erdma_dereg_mr;
	ibdev->post_send = erdma_post_send;
	ibdev->post_recv = erdma_post_recv;

	ibdev->req_notify_cq = erdma_req_notify_cq;
	ibdev->alloc_mr = erdma_ib_alloc_mr;
	ibdev->map_mr_sg = erdma_map_mr_sg;

	ibdev->create_ah = erdma_kzalloc_ah;
	ibdev->destroy_ah = erdma_destroy_ah;
	ibdev->get_netdev = erdma_get_netdev;
	ibdev->modify_cq = erdma_modify_cq;

	if (compat_mode) {
		ibdev->add_gid = erdma_add_gid;
		ibdev->del_gid = erdma_del_gid;
	}

	ibdev->iwcm->connect = erdma_connect;
	ibdev->iwcm->accept = erdma_accept;
	ibdev->iwcm->reject = erdma_reject;
	ibdev->iwcm->create_listen = erdma_create_listen;
	ibdev->iwcm->destroy_listen = erdma_destroy_listen;
	ibdev->iwcm->add_ref = erdma_qp_get_ref;
	ibdev->iwcm->rem_ref = erdma_qp_put_ref;
	ibdev->iwcm->get_qp = erdma_get_ibqp;
}
#endif

static int erdma_ib_device_add(struct pci_dev *pdev)
{
	struct erdma_dev *dev = pci_get_drvdata(pdev);
	struct ib_device *ibdev = &dev->ibdev;
	u64 mac;
	int ret;

	erdma_stats_init(dev);

	ret = erdma_dev_attrs_init(dev);
	if (ret)
		return ret;

#ifndef HAVE_UVERBS_CMD_MASK_NOT_NEEDED
	ibdev->uverbs_cmd_mask |=
		(1ull << IB_USER_VERBS_CMD_GET_CONTEXT) |
		(1ull << IB_USER_VERBS_CMD_QUERY_DEVICE) |
		(1ull << IB_USER_VERBS_CMD_QUERY_PORT) |
		(1ull << IB_USER_VERBS_CMD_ALLOC_PD) |
		(1ull << IB_USER_VERBS_CMD_DEALLOC_PD) |
		(1ull << IB_USER_VERBS_CMD_REG_MR) |
		(1ull << IB_USER_VERBS_CMD_DEREG_MR) |
		(1ull << IB_USER_VERBS_CMD_CREATE_COMP_CHANNEL) |
		(1ull << IB_USER_VERBS_CMD_CREATE_CQ) |
		(1ull << IB_USER_VERBS_CMD_DESTROY_CQ) |
		(1ull << IB_USER_VERBS_CMD_CREATE_QP) |
		(1ull << IB_USER_VERBS_CMD_QUERY_QP) |
		(1ull << IB_USER_VERBS_CMD_MODIFY_QP) |
		(1ull << IB_USER_VERBS_CMD_DESTROY_QP);
#endif

	if (compat_mode)
		ibdev->node_type = RDMA_NODE_IB_CA;
	else
		ibdev->node_type = RDMA_NODE_RNIC;
	memcpy(ibdev->node_desc, ERDMA_NODE_DESC, sizeof(ERDMA_NODE_DESC));

	/*
	 * Current model (one-to-one device association):
	 * One ERDMA device per net_device or, equivalently,
	 * per physical port.
	 */
	ibdev->phys_port_cnt = 1;
	ibdev->num_comp_vectors = dev->attrs.irq_num - 1;
#ifdef HAVE_DEV_PARENT
	ibdev->dev.parent = &pdev->dev;
#else
	ibdev->dma_device = &pdev->dev;
#endif

#ifdef HAVE_IB_DEV_OPS
	ib_set_device_ops(ibdev, &erdma_device_ops);
	if (compat_mode)
		ib_set_device_ops(ibdev, &erdma_compat_ops);
#else
	ibdev->iwcm = kmalloc(sizeof(struct iw_cm_verbs), GFP_KERNEL);
	if (!ibdev->iwcm)
		return -ENOMEM;

	erdma_ibverbs_init(ibdev);
#endif

	INIT_LIST_HEAD(&dev->cep_list);

	spin_lock_init(&dev->lock);
#ifdef HAVE_XARRAY
	xa_init_flags(&dev->qp_xa, XA_FLAGS_ALLOC1);
	xa_init_flags(&dev->cq_xa, XA_FLAGS_ALLOC1);
#else
	spin_lock_init(&dev->idr_lock);
	idr_init(&dev->qp_idr);
	idr_init(&dev->cq_idr);
#endif
	dev->next_alloc_cqn = 1;
	dev->next_alloc_qpn = 1;

	ret = erdma_res_cb_init(dev);
	if (ret) {
#ifndef HAVE_IB_DEV_OPS
		kfree(ibdev->iwcm);
#endif
		return ret;
	}

	spin_lock_init(&dev->db_bitmap_lock);
	bitmap_zero(dev->sdb_page, ERDMA_DWQE_TYPE0_CNT);
	bitmap_zero(dev->sdb_entry, ERDMA_DWQE_TYPE1_CNT);

	atomic_set(&dev->num_ctx, 0);

	mac = erdma_reg_read32(dev, ERDMA_REGS_NETDEV_MAC_L_REG);
	mac |= (u64)erdma_reg_read32(dev, ERDMA_REGS_NETDEV_MAC_H_REG) << 32;

	dev_info(&dev->pdev->dev, "assoc netdev mac addr is 0x%llx.\n", mac);

	u64_to_ether_addr(mac, dev->attrs.peer_addr);

	dev->db_pool = dma_pool_create("erdma_db", &pdev->dev, ERDMA_DB_SIZE,
				       ERDMA_DB_SIZE, 0);
	if (!dev->db_pool) {
		ret = -ENOMEM;
		goto err_out;
	}

	dev->reflush_wq = alloc_workqueue("erdma-reflush-wq", WQ_UNBOUND,
					  WQ_UNBOUND_MAX_ACTIVE);
	if (!dev->reflush_wq) {
		ret = -ENOMEM;
		goto free_pool;
	}

	ret = erdma_device_register(dev);
	if (ret)
		goto free_wq;

#ifdef HAVE_USE_CQ_DIM
	dev->ibdev.use_cq_dim = true;
#endif

	return 0;

free_wq:
	destroy_workqueue(dev->reflush_wq);
free_pool:
	dma_pool_destroy(dev->db_pool);
err_out:
#ifndef HAVE_IB_DEV_OPS
	kfree(ibdev->iwcm);
#endif

#ifdef HAVE_XARRAY
	xa_destroy(&dev->qp_xa);
	xa_destroy(&dev->cq_xa);
#else
	idr_destroy(&dev->qp_idr);
	idr_destroy(&dev->cq_idr);
#endif

	erdma_res_cb_free(dev);

	return ret;
}

static void erdma_ib_device_remove(struct pci_dev *pdev)
{
	struct erdma_dev *dev = pci_get_drvdata(pdev);

#ifndef HAVE_IB_DEVICE_GET_BY_NAME
	erdma_remove_dev_from_list(dev);
#endif

#ifndef HAVE_NETDEV_NOTIFIER_RH
	unregister_netdevice_notifier(&dev->netdev_nb);
#else
	unregister_netdevice_notifier_rh(&dev->netdev_nb);
#endif

	ib_unregister_device(&dev->ibdev);

	WARN_ON(atomic_read(&dev->num_ctx));
	WARN_ON(atomic_read(&dev->num_cep));
	WARN_ON(!list_empty(&dev->cep_list));

#ifndef HAVE_IB_DEV_OPS
	kfree(dev->ibdev.iwcm);
#endif
	erdma_res_cb_free(dev);
#ifdef HAVE_XARRAY
	xa_destroy(&dev->qp_xa);
	xa_destroy(&dev->cq_xa);
#else
	idr_destroy(&dev->qp_idr);
	idr_destroy(&dev->cq_idr);
#endif
	dma_pool_destroy(dev->db_pool);
	destroy_workqueue(dev->reflush_wq);
}

static int erdma_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	int ret;

	ret = erdma_probe_dev(pdev);
	if (ret)
		return ret;

	ret = erdma_ib_device_add(pdev);
	if (ret) {
		erdma_remove_dev(pdev);
		return ret;
	}

	return 0;
}

static void erdma_remove(struct pci_dev *pdev)
{
	erdma_ib_device_remove(pdev);
	erdma_remove_dev(pdev);
}

static struct pci_driver erdma_pci_driver = {
	.name = DRV_MODULE_NAME,
	.id_table = erdma_pci_tbl,
	.probe = erdma_probe,
	.remove = erdma_remove
};

MODULE_DEVICE_TABLE(pci, erdma_pci_tbl);

static __init int erdma_init_module(void)
{
	int ret;

	ret = erdma_cm_init();
	if (ret)
		return ret;

	ret = erdma_chrdev_init();
	if (ret)
		goto uninit_cm;

	ret = pci_register_driver(&erdma_pci_driver);
	if (ret) {
		pr_err("Couldn't register erdma driver.\n");
		goto uninit_chrdev;
	}

	return ret;

uninit_chrdev:
	erdma_chrdev_destroy();

uninit_cm:
	erdma_cm_exit();

	return ret;
}

static void __exit erdma_exit_module(void)
{
	pci_unregister_driver(&erdma_pci_driver);
	erdma_chrdev_destroy();
	erdma_cm_exit();
}

module_init(erdma_init_module);
module_exit(erdma_exit_module);
