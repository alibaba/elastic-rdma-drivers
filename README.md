# Alibaba Elastic RDMA Drivers

The Elastic RDMA (ERDMA) is released in Apsara Conference 2021 by Alibaba.
This repository contains the open source drivers for ERDMA:

* [Linux kernel driver](./kernel/) for Elastic RDMA Adapter (ERDMA)
* Official rdma-core with ERDMA support

Userspace Provider Initialization
=================================
If the rdma-core/ folder is empty, please use this command to get initialized:
```
git submodule update --init --recursive 
```
Then, use `scripts/patch_apply.sh` to apply the patches.
