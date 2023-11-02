Linux kernel driver for Elastic Rdma Adapter (ERDMA)
====================================================

Overview
========
Elastic RDMA Adapter (ERDMA) enables large-scale RDMA acceleration capability in Alibaba ECS environment, offered in all generation 8 instances.

It can improve the efficiency of large-scale distributed computing and communication significantly and expand dynamically with the cluster scale of Alibaba Cloud.

ERDMA is a RDMA networking adapter based on the Alibaba MOC hardware. It works in the VPC network environment (overlay network), and uses iWarp tranport protocol. ERDMA supports reliable connection (RC). ERDMA also supports both kernel space and user space verbs. Now we have already supported HPC/AI applications with libfabric, NoF and some other internal verbs libraries, such as xrdma, epsl, etc,.

For the ECS instance with RDMA enabled, our MOC hardware generates two kinds of PCI devices: one for ERDMA, and one for the original net device (virtio-net). They are separated PCI devices.

ERDMA depends on having ib_core and ib user verbs compiled with the kernel.

Driver compilation
==================
For list of supported kernels and distributions, please refer to the release notes documentation in the same directory.

Prerequisites
-------------

Kernel must be compiled with CONFIG_INFINIBAND_USER_ACCESS in Kconfig.

For CentOS or Redhat like OS:
```shell
   sudo yum update
   sudo yum install gcc cmake
   sudo yum install kernel-devel-$(uname -r)
   sudo yum install elfutils-libelf-devel
```

Compile steps
-------------

For compilation, run these commands:
```shell
   mkdir build
   cd build
   cmake ..
   make
```
erdma.ko is created inside the src/ folder.

Package Build
-------------

To build ERDMA packages:
- run `make` in the rpm/ folder if you are using CentOS like System, or 
- run `dpkg-buildpackage` in the root directory if you are using Debian or Ubuntu.
 
Your environment will need to be setup to build RPMs/DEBs. The ERDMA RPM/DEB will install the ERDMA kernel driver source, setup DKMS in order to build the driver when the kernel is updated, and update the configuration files to load ERDMA and its dependencies at boot time.

Driver installation
===================
Loading driver
--------------
Run command below to load the erdma module manually:
```shell
modprobe ib_core
modprobe ib_uverbs
insmod erdma.ko
```
For automatic driver start upon the OS boot:
```shell
sudo vi /etc/modules-load.d/erdma.conf
insert "erdma" to the file
copy the erdma.ko to /lib/modules/$(uname -r)/
sudo depmod -a
```
If previous driver was loaded from initramfs - it will have to be updated as well (i.e. dracut):
```
dracut --force  # in OS of CentOS/Alinux 
```

Restart the OS (sudo reboot and reconnect)

Supported PCI vendor ID/device IDs
==================================
1ded:107f - ERDMA used in ECS virtualized and bare-metal instances.

ERDMA Source Code Directory Structure (under src/)
================================================

|  Files |  Descriptions |
| ---- | ---- |
| erdma_main.c erdma.h |Main Linux kernel driver. |
| erdma_verbs.c erdma_cq.c erdma_qp.c  | Verbs implementations. |
| erdma_verbs.h | Verbs header. |
|erdma_cmdq.c | Management communication layer. This layer is responsible for the handling all the management (cmd) communication between the device and the driver. |
| erdma_cm.[ch] | Connection Management modules.|
| erdma_hw.h | Hardware related definitions. |
| erdma_debug.h | Debug Related definitions. |
| erdma_eq.c | Event Queue implementation. |
| erdma_ioctl.[ch] | Userspace diag interface (IOCTL). |
| erdma_stats.[ch] | Counter implementation to ib_core |
| erdma-abi.h | Kernel driver <-> Userspace provider ABI. |

Management Interface
====================
ERDMA management interface is exposed by means of:
- PCIe Configuration Space
- Device Registers
- Command Queue (CMDQ) and CMD Completion Queue (CMD-CQ)
- Asynchronous Event Queue (AEQ)

CMDQ is used for submitting management commands, and the
results/responses are reported asynchronously through CMD-CQ.

ERDMA introduces a small set of management commands.
Most of the management operations are framed in a generic get/set feature
command.

The following CMDQ commands are supported:
- Create/Destroy Queue Pair
- Create/Destroy Completion Queue
- Create/Destroy Memory Region
- Query device capability
- Create/Destroy Completion Event Queue
- Query device version.

The Asynchronous Event Queue (AEQ) is a unidirectional queue used by the ERDMA device to send to the driver events that cannot be reported using CEQ. AEQ events are subdivided into groups. Each
group may have multiple syndromes, as shown below:

CMD-CQ and AEQ share the same MSI-X vector.

Interrupt Modes
===============
ERDMA device supports interrupt mode. The The maximum interrupt number is 32 per device: one is Common interrupt, and the rest are completion interrupts.

How many IRQ vectors the driver try to request is depends on the # of online CPUs. We won't try to request more than `# of online CPUs + 1 ` vectors.

Common interrupt (for CMD-CQ and AEQ) registration is performed when the Linux kernel probes the adapter, and it is un-registered when the adapter is removed.

The management interrupt is named:
```
erdma-common@pci:\<*PCI domain*:*bus*:*slot*.*function*\>
```
The completion interrupt in named:
```
erdma-ceqX@pci:\<*PCI domain*:*bus*:*slot*.*function*\>
```

Data Path Interface
===================
I/O operations are based on Queue Pairs (QPs) - Send Queues (SQs) and Receive Queues (RQs).  Each queue has a Completion Queue (CQ) associated with it.

The QPs and CQs are implemented as Work/Completion Queue Elements (WQEs/CQEs) rings with contiguous physical memory in kernel or scatter pages in userspace.

The ERDMA supports DirectWQE (DWQE) mode for SQs: In this mode the userspace provider writes the WQEs directly to the ERDMA device memory space, while the packet data resides in the host's memory.

The RQs reside in the host's memory. The ERDMA device fetches the RQEs and packet data from host memory.

The user notifies the ERDMA device of new WQEs by writing to a dedicated PCI device memory BAR referred as Doorbells BAR which is mapped to the userspace provider.

Insight the Module
===================
The kernel of higher version has strong ability and interface to insight the status of each IB device, but many older kernel can not do this perfectly.

To unify the code, we provides a char device in the all module to allow the users can get necessary information about the status of IB device. The corresponding userspace diagnosis tool is named *eadm* (which will be opened later).

We also provides a custom debug print system for log print easily.

Note that these methods does not influence the built-in method in new kernel.