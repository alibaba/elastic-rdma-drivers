# ERDMA Linux Kernel Driver Release Notes

## Supported Kernel Versions and Distributions
Generally speaking, this driver already support for almost all current
distributions of CentOS, Ubuntu, Alinux and Anolis. But for stability,
verified systems is recommended which listed below:
* CentOS 7.6/7.9/8.4/8.5
* Ubuntu 18.04/22.04
* Alinux 2/3
* Anolis 8.4/8.5

## r0.2.37
* RDMA/erdma: Add d-ack capbility and d-ack count setting support
* RDMA/erdma: Add get_vecotr_affinity support
* RDMA/erdma: Add SMC-R IPv6 support and do some cleaning
* RDMA/erdma: Add rendezvous flag and remote qpn in modifying SMC-R qp
* RDMA/erdma: No shift in page size field in REG MR wr
* RDMA/erdma: Add page size available bit and page size field
* RDMA/erdma: Clear the size field in MR because some MOC versions check it
* RDMA/erdma: Add IPv6 support for iwarp mode and OOB mode
* RDMA/erdma: Use fixed default device name
* RDMA/erdma: Revert compat_mode port immutable implementation
* RDMA/erdma: Fix wrong usage of wrlock
* RDMA/erdma: Reduce compat_mode usage
* RDMA/erdma: Unify create_ah/destroy_ah interface
* RDMA/erdma: Remove unused register definitions.
* RDMA/erdma: Refactor compat related code to [k|erdma_]compat.h
* RDMA/erdma: Format code style by clang-format
* RDMA/erdma: Support scatter mtt
* RDMA/erdma: Refactor MTT buffer management
* RDMA/erdma: Optimize some macro definitions and add new fields of CMD
* RDMA/erdma: Add atomic operation support for kernel verbs
* RDMA/erdma: Change position of some related definitions
* RDMA/erdma: Fix memleak in mad qp destroying

## r0.2.36
* RDMA/erdma: Add copyright of build script
* RDMA/erdma: Refactor cmake build script
* RDMA/erdma: Update CMakefile to fix compat mode default
* RDMA/erdma: Add RDMA_CM support for compat mode
* RDMA/erdma: Report pkey_tbl_len = 1 in compat_mode
* RDMA/erdma: Do not print QP info if QP type is not RC
* RDMA/erdma: Fix some compat issues
* RDMA/erdma: Sync code from egs version
* RDMA/erdma: Sync code from upstream
* RDMA/erdma: Use ratelimited print function to print error message
* RDMA/erdma: Remove erdma_debug.h file
* RDMA/erdma: Update cmake version to 2.8.12 and sync code from upstream
* RDMA/erdma: Sync code to upstream kernel.
* RDMA/erdma: Use xxx_to_xxx APIs instead of __xxx_to_xxx APIs
* RDMA/erdma: Fix compile error if MLNX OFED not exists
* RDMA/erdma: reset device before init if necessary
* RDMA/erdma: Use Big Endian port num in compat mode

## r0.2.35
* Support query kernel qp information
* Fix mmap_free missing for some OS
* Support MLNX OFED
* Inline mtt support up to 4 entries.
* Increase EQ depth to 4096
* Fix eadm display wrong QP information
* Using custom hardware page size instead of kernel page size
* Limit error print rate in init_kernel_qp
* Add OOB support of Ubuntu18.04
* Add random qpn support.
* Add configurable reserved ports bases support.
* Send set mtu command in init phase.
* Update oob connection info in modify qp
* Add restransmit num set support

## r0.2.34
* Issue reflush cmd when QP state changed to CLOSING.

## r0.2.33
* Support modify cq in linux 4.19
* RDMA/erdma: Double the max_send_wr capacity (4096 -> 8192)
* Rename and change type of EQ doorbell
* RDMA/erdma: Refactor the device initialization flow
* Support hardware statistic counters
* RDMA/erdma: Support reflush instead of original drain QP implementation
* RDMA/erdma: Fix coding style issues and fix ioctl-stats memory leak issue
* RDMA/erdma: Modify qp to error when calling erdma_qp_llp_close

## r0.2.32
* RDMA/erdma: Support dynamic mtu
* RDMA/erdma: Make hardware internal opcodes invisible to driver
* RDMA/erdma: Query atomic capability from hw
* RDMA/erdma: Remove redundant includes
* RDMA/erdma: Support newest kernel compilation

## r0.2.31
* Support atomic operation.

## r0.2.30
* Support config mtu to MOC.

## r0.2.29
* Fix NULL pointer problem in drain qp

## r0.2.28
* Simplity the compat macro

## r0.2.27
* Simplity the return value check of erdma_recv_mpa_rr
* Change code license to BSD-3-Clause (original is OpenIB)
* RDMA/erdma: Use non-atomic bit API in spin_lock.

## r0.2.26 release notes
* Fix port num in out-bound connection

## r0.2.25 release notes
* Support pkey_tbl_len

## r0.2.24 release notes
* Add hrtimer cancel to avoid hrtimer waking after cq being destroyed.
* Fix the size in dma-free-coherent.

## r0.2.23 release notes
* Add get netdev to lower kernel version to support SMC-R

## r0.2.22 release notes
* Fix returned wrong value when using eadm dump

## r0.2.21 release notes
* Use dma pool to alloc db info for sq and rq.

## r0.2.20 release notes
* Use defer probe to solve net device not being probed in time.

## r0.2.19 release notes
* Add modify cq to support DIM.
* Remove notify cq operation with related flag when there is more cqe.

## r0.2.18 release notes
* Support ioctl in older OS
* Modify the assoc logic between erdma and eni devices.

## r0.2.16 release notes
* Add more ioctl dump command support.

## r0.2.15 release notes
* Fix a oops with wrong perftest command.

## r0.2.13
* Support inline mtt with create_qp command to MOC.
* Fix loopback connection failure in Debian9.

## r0.2.11 release notes
* Fix issue: in some OS kernel, can not reach the maximum number of QP/CQ

## r0.2.10 release notes
* support loopback test in centos.

## r0.2.9 release notes
* Fix a condition race in cm module
* Do not issue a CMD message to MOC when calling modify_qp in destroy_qp

## r0.2.8 release notes
* Revert modify qp to rts issues

## r0.2.7 release notes
* No longer motify_qp to ERROR state in destroy_qp

## r0.2.6 release notes
* Fix bug in compat_mode
* Support other OS compilation
* Fix memory leak in mmap

## r0.2.4 release notes
* Fix wrong core_cap_flags in compat_mode

## r0.2.3 release notes
* Fix wrong max_mr_size display

## r0.2.2 release notes
* Fix report CQEs after destroy_qp

## r0.2.1 release notes
* Add version query to eadm
* Fix oops with no numa VMs.

## r0.2.0 release notes
* Add version match mechanism
* Fix FRMR in post_send with no clear fields.

## r0.1.3 release notes
* Support GDR
