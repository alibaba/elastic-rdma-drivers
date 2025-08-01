# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
# Copyright 2022 Alibaba.com, Inc.
# Copyright 2021 Amazon.com, Inc. or its affiliates. All rights reserved.

function(config_define def)
  file(APPEND ${CMAKE_CURRENT_BINARY_DIR}/config.h "#define ${def} 1\n")
endfunction()

function(set_conf_tmp_dir prologue body)
  string(RANDOM rand)
  set(tmp_dir "tmp_${rand}")
  set(tmp_dir ${tmp_dir} PARENT_SCOPE)
  configure_file(${CMAKE_SOURCE_DIR}/config/main.c.in ${tmp_dir}/main.c @ONLY)
  configure_file(${CMAKE_SOURCE_DIR}/config/Makefile ${tmp_dir} COPYONLY)
  configure_file(${CMAKE_SOURCE_DIR}/src/ofa.mk ${tmp_dir} COPYONLY)
endfunction()

function(try_compile_prog_test)
  set_conf_tmp_dir("" "")
  execute_process(COMMAND make -C ${tmp_dir} KERNEL_DIR=${KERNEL_DIR} OFA_DIR=${OFA_DIR}
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    OUTPUT_QUIET ERROR_QUIET
    RESULT_VARIABLE res)
  if(res)
    message(FATAL_ERROR "Conftest failure, kernel headers missing?")
  endif()
  file(REMOVE_RECURSE ${CMAKE_CURRENT_BINARY_DIR}/${tmp_dir})
endfunction()

function(wait_for_pid pid)
  execute_process(COMMAND ${CMAKE_SOURCE_DIR}/config/wait_for_pid.sh ${pid})
endfunction()

function(wait_for_pids)
  # Wait for everyone to finish
  foreach(pid ${pids})
    wait_for_pid(${pid})
  endforeach()
endfunction()

function(process_rl)
  list(LENGTH pids list_len)
  if(list_len EQUAL max_process)
    list(GET pids 0 pid)
    wait_for_pid(${pid})
    list(REMOVE_AT pids 0)
    set(pids "${pids}" CACHE INTERNAL "")
  endif()
endfunction()

# CMake "global" variable
set(pids "" CACHE INTERNAL "")

include(ProcessorCount)
ProcessorCount(max_process)

function(try_compile prologue body success_def fail_def)
  # Rate limit processes
  process_rl()
  set_conf_tmp_dir("${prologue}" "${body}")
  execute_process(COMMAND ${CMAKE_SOURCE_DIR}/config/runbg.sh ${CMAKE_SOURCE_DIR}/config/compile_conftest.sh ${CMAKE_CURRENT_BINARY_DIR}/${tmp_dir} ${KERNEL_DIR} ${OFA_DIR} "${success_def}" "${fail_def}"
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    OUTPUT_STRIP_TRAILING_WHITESPACE
    OUTPUT_VARIABLE pid)
  list(APPEND pids ${pid})
  set(pids "${pids}" CACHE INTERNAL "")
endfunction()

function(try_compile_dev_or_ops fp_name fn_name fn success_def fail_def)
  try_compile("${fn}"
  "
struct ib_device_ops ops = {
  .${fp_name} = ${fn_name},
};
  "
  "${success_def}" "${fail_def}")

  try_compile("${fn}"
  "
struct ib_device ibdev = {
  .${fp_name} = ${fn_name},
};
  "
  "${success_def}" "${fail_def}")
endfunction()

file(REMOVE ${CMAKE_CURRENT_BINARY_DIR}/config.h)
file(REMOVE ${CMAKE_CURRENT_BINARY_DIR}/../output.log)

message("-- Inspecting kernel")
try_compile_prog_test()

try_compile("#include <rdma/ib_umem.h>" "struct ib_umem_chunk chunk;" "" "HAVE_UMEM_SCATTERLIST_IF")

try_compile("#include <rdma/ib_umem.h>"
  "
  struct sg_append_table table;
struct ib_umem umem = {
  .sgt_append = table,
};
  "
  HAVE_UMEM_SGT_APPEND "")

try_compile("" "struct ib_cq_init_attr attr;" HAVE_CREATE_CQ_ATTR "")

try_compile("" "struct rdma_ah_attr attr;" HAVE_CREATE_AH_RDMA_ATTR "")

try_compile(""
  "
struct device dev = {
  .dma_ops = NULL,
};
  "
  HAVE_DEV_PARENT "")

try_compile(""
  "
struct device_rh dev = {
  .dma_ops = NULL,
};
  "
  HAVE_DEV_PARENT "")

try_compile_dev_or_ops(post_send erdma_post_send
  "
static int erdma_post_send(struct ib_qp *ibqp, const struct ib_send_wr *wr, const struct ib_send_wr **bad_wr)
  { return 0; }
  "
  HAVE_POST_CONST_WR "")

try_compile(""
  "
struct ib_device_attr attr = {
  .max_send_sge = 0,
  .max_recv_sge = 0,
};
  "
  HAVE_MAX_SEND_RCV_SGE "")

try_compile("int port_callback(struct ib_device *ibdev, u8 n, struct kobject *kobj) { return 0; }"
  "
char name[2];
ib_register_device(NULL, name, port_callback);
  "
  HAVE_IB_REGISTER_DEVICE_NAME_PARAM "")

try_compile("" "ib_modify_qp_is_ok(0, 0, 0, 0);" HAVE_IB_MODIFY_QP_IS_OK_FOUR_PARAMS "")

try_compile(""
  "
pgprot_t prot;
rdma_user_mmap_io(NULL, NULL, 0, 0, prot);
  "
  HAVE_RDMA_USER_MMAP_IO "")

try_compile("" "struct ib_device_ops ops;" HAVE_IB_DEV_OPS "")

try_compile_dev_or_ops(create_ah erdma_kzalloc_ah
  "struct ib_ah *erdma_kzalloc_ah(struct ib_pd *ibpd, struct rdma_ah_attr *ah_attr, u32 flags, struct ib_udata *udata) { return NULL; }"
  HAVE_CREATE_AH_FLAGS "")

try_compile_dev_or_ops(destroy_ah erdma_destroy_ah
  "void erdma_destroy_ah(struct ib_ah *ibah, u32 flags) {}"
  HAVE_DESTROY_AH_VOID "")

try_compile_dev_or_ops(destroy_ah erdma_destroy_ah
  "int erdma_destroy_ah(struct ib_ah *ibah, u32 flags) { return 0; }"
  HAVE_DESTROY_AH_FLAGS "")

try_compile(
  "
#include <linux/scatterlist.h>
#include <rdma/ib_umem.h>
  "
  "
int i;
struct ib_umem *umem;
struct sg_dma_page_iter *sg_iter;
for_each_sg_dma_page(umem->sg_head.sgl, sg_iter, umem->nmap, 0)
	i++;
  "
  HAVE_SG_DMA_PAGE_ITER "")

try_compile(""
  "
struct ib_device_ops ops = {
  .size_ib_pd = 0,
};
  "
  HAVE_PD_CORE_ALLOCATION "")

try_compile(""
  "
struct ib_device_ops ops = {
  .size_ib_ucontext = 0,
};
  "
  HAVE_UCONTEXT_CORE_ALLOCATION "")

try_compile(""
  "
struct ib_device dev = {
  .kverbs_provider = 0,
};
  "
  HAVE_NO_KVERBS_DRIVERS "")

try_compile("#include <rdma/ib_umem.h>"
  "
struct ib_udata *udata;
ib_umem_get(udata, 0, 0, 0, 0);
  "
  HAVE_IB_UMEM_GET_UDATA "")

try_compile(
  "
#include <rdma/uverbs_ioctl.h>

struct erdma_ucontext {
	struct ib_ucontext ibucontext;
};
  "
  "
struct ib_udata *udata;
rdma_udata_to_drv_context(udata, struct erdma_ucontext, ibucontext);
  "
  HAVE_UDATA_TO_DRV_CONTEXT "")

try_compile(""
  "
struct ib_device *dev;
char name[2];
ib_register_device(dev, name);
  "
  HAVE_IB_REGISTER_DEVICE_TWO_PARAMS "")

try_compile(
  "
struct erdma_dev {
  struct ib_device ibdev;
};
  "
  "ib_alloc_device(erdma_dev, ibdev);" HAVE_SAFE_IB_ALLOC_DEVICE "")

try_compile(""
  "
struct ib_device_ops ops = {
  .size_ib_ah = 0,
};
  "
  HAVE_AH_CORE_ALLOCATION "")

try_compile_dev_or_ops(alloc_pd erdma_alloc_pd
  "int erdma_alloc_pd(struct ib_pd *ibpd, struct ib_udata *udata) { return 0; }"
  HAVE_ALLOC_PD_NO_UCONTEXT "")

try_compile_dev_or_ops(create_cq erdma_kzalloc_cq
  "struct ib_cq *erdma_kzalloc_cq(struct ib_device *ibdev, const struct ib_cq_init_attr *attr, struct ib_udata *udata) { return NULL; }"
  HAVE_CREATE_CQ_NO_UCONTEXT "")

try_compile_dev_or_ops(dealloc_pd erdma_dealloc_pd
  "void erdma_dealloc_pd(struct ib_pd *ibpd, struct ib_udata *udata) {}"
  HAVE_DEALLOC_PD_UDATA "")

try_compile_dev_or_ops(dereg_mr erdma_dereg_mr
  "int erdma_dereg_mr(struct ib_mr *ibmr, struct ib_udata *udata) { return 0; }"
  HAVE_DEREG_MR_UDATA "")

try_compile_dev_or_ops(add_gid erdma_add_gid
  "int erdma_add_gid(const struct ib_gid_attr *attr, void **context) { return 0; }"
  HAVE_OLD_GID_OPERATION "")

try_compile_dev_or_ops(destroy_cq erdma_destroy_cq
  "int erdma_destroy_cq(struct ib_cq *ibcq, struct ib_udata *udata) { return 0; }"
  HAVE_DESTROY_CQ_UDATA "")

try_compile_dev_or_ops(destroy_qp erdma_destroy_qp
  "int erdma_destroy_qp(struct ib_qp *ibqp, struct ib_udata *udata) { return 0; }"
  HAVE_DESTROY_QP_UDATA "")

try_compile_dev_or_ops(create_ah erdma_create_ah
  "int erdma_create_ah(struct ib_ah *ibah, struct rdma_ah_init_attr *init_attr, struct ib_udata *udata) { return 0; }"
  HAVE_CREATE_AH_RDMA_INIT_ATTR "")

try_compile("#include <rdma/ib_umem.h>" "ib_umem_find_best_pgsz(NULL, 0, 0);"
  HAVE_IB_UMEM_FIND_SINGLE_PG_SIZE "")

try_compile("" "enum rdma_driver_id driver_id = RDMA_DRIVER_ERDMA;"
  HAVE_UPSTREAM_ERDMA "")

try_compile(""
  "
struct ib_device_ops ops = {
  .driver_id = 0,
};
  "
  HAVE_IB_DEVICE_OPS_COMMON "")

try_compile_dev_or_ops(destroy_cq erdma_destroy_cq
  "void erdma_destroy_cq(struct ib_cq *ibcq, struct ib_udata *udata) {}"
  HAVE_IB_VOID_DESTROY_CQ "")

try_compile("void erdma_destroy_cq(struct ib_cq *ibcq, struct ib_udata *udata) {}"
  "
struct ib_device_ops ops = {
  .size_ib_cq = 0,
};
  "
  HAVE_CQ_CORE_ALLOCATION "")

try_compile("void erdma_destroy_cq(struct ib_cq *ibcq, struct ib_udata *udata) {}"
  "int a = IB_PORT_PHYS_STATE_LINK_UP;"
  HAVE_IB_PORT_PHYS_STATE_LINK_UP "")

try_compile("#include <linux/mm.h>" "kvzalloc(0, 0);" HAVE_KVZALLOC "")

try_compile(""
  "
struct ib_device *dev;
ibdev_err_ratelimited(dev, \"Hello\");
  "
  HAVE_IBDEV_PRINT_RATELIMITED "")

try_compile(""
  "
struct ib_device *dev;
ibdev_err(dev, \"World\");
  "
  HAVE_IBDEV_PRINT "")

try_compile("" "int a = IB_QPT_DRIVER;" HAVE_IB_QPT_DRIVER "")

try_compile("" "ib_is_udata_cleared(NULL, 0, 0);" HAVE_IB_IS_UDATA_CLEARED "")

try_compile(""
  "
struct ib_device dev = {
  .driver_id = 0,
};
  "
  HAVE_DRIVER_ID "")

try_compile(""
  "
struct ib_mr mr = {
  .length = 0,
};
  "
  HAVE_IB_MR_LENGTH "")

try_compile("#include <linux/pci_ids.h>" "int a = PCI_VENDOR_ID_ALIBABA;"
  HAVE_PCI_VENDOR_ID_ALIBABA "")

try_compile("#include <rdma/ib_umem.h>" "ib_umem_get(NULL, 0, 0, 0);"
  HAVE_IB_UMEM_GET_NO_DMASYNC "")

try_compile("#include <rdma/ib_umem.h>"
  "
pgprot_t pgt;
rdma_user_mmap_io(NULL, NULL, 0, 0, pgt, NULL);
  "
  HAVE_CORE_MMAP_XA "")

try_compile("" "int a = RDMA_NODE_UNSPECIFIED;" HAVE_RDMA_NODE_UNSPECIFIED "")

try_compile("#include <linux/bitfield.h>" "" HAVE_BITFIELD_H "")

try_compile("#include <rdma/ib_umem.h>"
  "
struct ib_device *dev;
ib_umem_get(dev, 0, 0, 0);
  "
  HAVE_IB_UMEM_GET_DEVICE_PARAM "")

try_compile("" "int a = IB_ACCESS_OPTIONAL;" HAVE_IB_ACCESS_OPTIONAL "")

try_compile("" "atomic64_fetch_inc(NULL);" HAVE_ATOMIC64_FETCH_INC "")

try_compile_dev_or_ops(dealloc_pd erdma_dealloc_pd
  "int erdma_dealloc_pd(struct ib_pd *ibpd, struct ib_udata *udata) { return 0; }"
  HAVE_DEALLOC_PD_UDATA_RC "")

try_compile_dev_or_ops(destroy_cq erdma_destroy_cq
  "int erdma_destroy_cq(struct ib_cq *ibcq, struct ib_udata *udata) { return 0; }"
  HAVE_IB_INT_DESTROY_CQ "")

try_compile("#include <rdma/ib_umem.h>"
  "
struct ib_block_iter biter;
struct ib_umem *umem;
int i;

rdma_umem_for_each_dma_block(umem, &biter, 0)
  i++;
  "
  HAVE_RDMA_UMEM_FOR_EACH_DMA_BLOCK "")

try_compile("#include <rdma/ib_umem.h>"
  "
struct ib_umem *umem;

ib_umem_num_dma_blocks(umem, 0);
  "
  HAVE_IB_UMEM_NUM_DMA_BLOCKS "")

try_compile(""
  "
struct ib_device *dev;
char name[2];
struct device *dma_device;
ib_register_device(dev, name, dma_device);
  "
  HAVE_IB_REGISTER_DEVICE_DMA_DEVICE_PARAM "")

try_compile_dev_or_ops(create_user_ah erdma_create_ah
  "int erdma_create_ah(struct ib_ah *ibah, struct rdma_ah_init_attr *init_attr, struct ib_udata *udata) { return 0; }"
  HAVE_UVERBS_CMD_MASK_NOT_NEEDED "")

try_compile_dev_or_ops(query_port erdma_query_port
  "int erdma_query_port(struct ib_device *ibdev, u32 port, struct ib_port_attr *props) { return 0; }"
  HAVE_U32_PORT "")

try_compile_dev_or_ops(alloc_hw_port_stats erdma_alloc_hw_port_stats
  "struct rdma_hw_stats *erdma_alloc_hw_port_stats(struct ib_device *ibdev, u32 port_num) { return 0; }"
  HAVE_SPLIT_STATS_ALLOC "")

try_compile_dev_or_ops(alloc_hw_stats erdma_alloc_hw_stats
  "struct rdma_hw_stats *erdma_alloc_hw_stats(struct ib_device *ibdev, u8 port_num ) { return NULL; }"
  HAVE_SINGLE_HW_STATS "")

try_compile_dev_or_ops(alloc_hw_stats erdma_alloc_hw_stats
  "struct rdma_hw_stats *erdma_alloc_hw_stats(struct ib_device *ibdev, u32 port_num ) { return NULL; }"
  HAVE_SINGLE_HW_STATS "")

try_compile_dev_or_ops(get_vector_affinity erdma_get_vector_affinity
  "const struct cpumask *erdma_get_vector_affinity(struct ib_device *ibdev, int comp_vector) { return NULL; }"
  HAVE_GET_VECTOR_AFFINITY "")

try_compile("#include <linux/sysfs.h>"
  "
sysfs_emit(NULL, \"Test\");
  "
  HAVE_SYSFS_EMIT "")

try_compile("#include <linux/xarray.h>" "xa_load(NULL, 0);" HAVE_XARRAY_API "")

try_compile(""
  "
struct ib_device_ops ops = {
  .size_ib_qp = 0,
};
  "
  HAVE_QP_CORE_ALLOCATION "")

try_compile("" "struct rdma_stat_desc desc;" HAVE_STAT_DESC_STRUCT "")

# dynamic DMA-buf handling and ibcore device method are required.
try_compile_dev_or_ops(reg_user_mr_dmabuf erdma_reg_user_mr_dmabuf "
#include <linux/dma-resv.h>
#include <linux/dma-buf.h>
static struct dma_buf_attachment a = { .importer_priv = NULL };
struct ib_mr *erdma_reg_user_mr_dmabuf(struct ib_pd *ibpd, u64 start, u64 length, u64 virt_addr,
                                     int fd, int access_flags, struct ib_udata *udata) { return 0; }"
  HAVE_MR_DMABUF "")

try_compile("#include <rdma/ib_umem.h>" "ib_umem_dmabuf_get_pinned(NULL, 0, 0, 0, 0);" HAVE_IB_UMEM_DMABUF_PINNED "")

try_compile("#include <rdma/ib_verbs.h>"
  "
struct iw_ext_conn_param param;
  "
  HAVE_IWARP_OUTBOUND_QP_CREATE_FOR_SMC "")

try_compile("#include <linux/tcp.h>"
  "
struct sock *sk;
sk->sk_data_ready(sk);
  "
  HAVE_SK_DATA_READY_ONE_PARAM "")

try_compile("#include <linux/tcp.h>"
  "
tcp_sock_set_nodelay(NULL);
  "
  HAVE_TCP_SOCK_SET_NODELAY "")

try_compile("#include <net/sock.h>"
  "
sock_set_reuseaddr(NULL);
  "
  HAVE_SK_SET_REUSEADDR "")

try_compile("#include <rdma/ib_umem.h>"
  "
struct ib_umem *umem;

ib_umem_num_pages(umem);

  "
  HAVE_IB_UMEM_NUM_PAGES "")

try_compile("#include <rdma/ib_verbs.h>"
  "
rdma_set_device_sysfs_group(NULL, NULL);

  "
  HAVE_RDMA_SET_DEVICE_SYSFS_GROUP "")

try_compile("#include <rdma/ib_verbs.h>"
  "
ib_device_set_netdev(NULL, NULL, 0);
  "
  HAVE_IB_DEVICE_SET_NETDEV "")

try_compile("#include <rdma/ib_verbs.h>"
  "
ib_device_get_by_name(NULL, 0);
  "
  HAVE_IB_DEVICE_GET_BY_NAME "")

try_compile("#include <linux/rtnetlink.h>"
  "
void *p = &net_rwsem;
  "
  HAVE_NET_RWSEM "")

try_compile("#include <rdma/ib_verbs.h>"
  "
struct rdma_restrack_entry entry = {
	.user = 1,
};
  "
  HAVE_RDMA_RESTRACK_ENTRY_USER ""
)

try_compile("#include <net/sock.h>"
  "
struct socket s;
struct sockaddr_storage a;
s.ops->getname(&s, (struct sockaddr *)&a, 0);
  "
  HAVE_SOCK_OPS_GET_NAME_THREE_PARAM ""
)

try_compile("#include <linux/netdevice.h>"
  "
register_netdevice_notifier_rh(NULL);
  "
  HAVE_NETDEV_NOTIFIER_RH ""
)


try_compile("#include <linux/etherdevice.h>"
  "
u64_to_ether_addr(0, NULL);
  "
  HAVE_ETHERDEVICE_HELPER ""
)

try_compile("#include <rdma/ib_verbs.h>"
  "
ib_mtu_int_to_enum(0);
  "
  HAVE_IB_MTU_INT_TO_ENUM ""
)

try_compile("#include <rdma/ib_verbs.h>"
  "
struct ib_cq cq;
void *tmp = (void *)&cq.res;
  "
  HAVE_IB_CQ_WITH_RES ""
)

try_compile("#include <linux/sched/task.h>"
  "
int i;
  "
  HAVE_HEADER_LINUX_SCHED_TASK ""
)

try_compile("#include <linux/sched/signal.h>"
  "
int i;
  "
  HAVE_HEADER_LINUX_SCHED_SIGNAL ""
)

try_compile_dev_or_ops(alloc_mr erdma_ib_alloc_mr
  "struct ib_mr *
  erdma_ib_alloc_mr(struct ib_pd *ibpd, enum ib_mr_type mr_type, u32 max_num_sg) { return NULL; }"
  HAVE_ALLOC_MR_NO_UDATA "")

try_compile("#include <rdma/ib_verbs.h>"
  "
struct ib_global_route gr = {
  .sgid_attr = NULL,
};
  "
  HAVE_IB_GLOBAL_ROUTE_WITH_SGID_ATTR ""
)

try_compile(""
  "
struct ib_device dev = {
  .use_cq_dim = 0,
};
  "
  HAVE_USE_CQ_DIM "")

try_compile("#include <linux/kref.h>"
  "
kref_read(NULL);
  "
  HAVE_KREF_READ ""
)

try_compile("#include <rdma/ib_verbs.h>"
  "
  u32 flags = IBK_LOCAL_DMA_LKEY;
  "
  HAVE_NEW_DEVICE_CAP_FLAGS ""
)

try_compile("#include <rdma/ib_umem.h>"
  "
  struct ib_device *ibdev;
  ib_umem_get_peer(ibdev, 0, 0, 0 ,0);
  "
  HAVE_IB_UMEM_GET_PEER_DEVICE ""
)

try_compile("#include <rdma/ib_umem.h>"
  "
  struct ib_udata *udata;
  ib_umem_get_peer(udata, 0, 0, 0 ,0);
  "
  HAVE_IB_UMEM_GET_PEER_UDATA ""
)

try_compile("#include <linux/netdevice.h>"
  "
struct net_device netdev = {
  .lower_level = 0,
};
  "
  HAVE_LOWER_LEVEL_IN_NET_DEVICE ""
)

try_compile("#include <rdma/ib_verbs.h>" "ib_device_get_by_netdev(NULL, 0);"
  HAVE_IB_DEVICE_GET_BY_NETDEV "")

try_compile("#include <net/ip.h>" "ip_local_out(NULL, NULL, NULL);"
  HAVE_IP_LOCAL_OUT_NET_SOCK "")

try_compile("#include <net/ip.h>" "ip_local_out(NULL);"
  HAVE_IP_LOCAL_OUT_SKB "")

try_compile("#include <linux/net.h>"
  "sock_create_kern(AF_INET, SOCK_DGRAM, 0, NULL);"
  HAVE_SOCK_NO_NET_PARAM "")

try_compile("#include <rdma/ib_cache.h>" "rdma_read_gid_attr_ndev_rcu(NULL);"
  HAVE_RDMA_READ_GID_ATTR_NDEV_RCU "")

try_compile("#include <rdma/ib_cache.h>"
  "
  rdma_get_gid_attr(NULL, 0, 0);
  "
  HAVE_RDMA_GID_API ""
)

try_compile("#include <rdma/ib_cache.h>"
  "
  rdma_find_gid_by_port(NULL, NULL, 0, 0, NULL);
  "
  HAVE_RDMA_FIND_GID_BY_PORT ""
)

try_compile("#include <rdma/ib_verbs.h>"
  "
  int flags = IB_QP_CREATE_IWARP_WITHOUT_CM;
  "
  HAVE_IB_QP_CREATE_IWARP_WITHOUT_CM ""
)

try_compile("#include <linux/bitfield.h>"
  "
  be32_to_cpu_array(NULL, NULL, 1);
  "
  HAVE_BYTEORDER_ARRAY_API ""
)

try_compile("#include <linux/netdevice.h>"
  "
struct net_device netdev = {
  .lower_level = 0,
};
  "
  HAVE_LOWER_LEVEL_IN_NET_DEVICE ""
)

try_compile("#include <linux/rtnetlink.h>"
  "
down_read(&net_rwsem);
  "
  HAVE_NET_RWSEM ""
)

wait_for_pids()
message("-- Inspecting kernel - done")
