/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * Copyright (c) 2020-2022, Alibaba Group.
 * Copyright 2019-2021 Amazon.com, Inc. or its affiliates. All rights reserved.
 */

#ifndef _ERDMA_P2P_H_
#define _ERDMA_P2P_H_

#include "erdma.h"
#include "erdma_verbs.h"

struct erdma_p2p_ops {
	struct erdma_p2pmem *(*try_get)(struct erdma_dev *dev, u64 ticket, u64 start,
				      u64 length);
	int (*to_page_list)(struct erdma_dev *dev, struct erdma_p2pmem *p2pmem,
			    u64 *page_list);
	void (*release)(struct erdma_dev *dev, struct erdma_p2pmem *p2pmem,
			bool in_cb);
	unsigned int (*get_page_size)(struct erdma_dev *dev,
				      struct erdma_p2pmem *p2pmem);
};

enum erdma_p2p_prov {
	ERDMA_P2P_PROVIDER_NVMEM,
	ERDMA_P2P_PROVIDER_MAX,
};

struct erdma_p2p_provider {
	const struct erdma_p2p_ops ops;
	enum erdma_p2p_prov type;
};

struct erdma_p2pmem {
	struct erdma_dev *dev;
	const struct erdma_p2p_provider *prov;
	u64 ticket;
	u32 lkey;
	struct ib_mr *ibmr;
	bool needs_dereg;
	struct list_head list; /* member of erdma_p2p_list */
};

void erdma_p2p_init(void);
struct erdma_p2pmem *erdma_p2p_get(struct erdma_dev *dev, struct erdma_mr *mr, u64 start,
			       u64 length);
unsigned int erdma_p2p_get_page_size(struct erdma_dev *dev,
				   struct erdma_p2pmem *p2pmem);
int erdma_p2p_to_page_list(struct erdma_dev *dev, struct erdma_p2pmem *p2pmem,
			 u64 *page_list);
int erdma_p2p_put(u64 ticket, bool in_cb);

/* Provider specific stuff go here */
const struct erdma_p2p_provider *nvmem_get_provider(void);
bool nvmem_is_supported(void);

#endif /* _ERDMA_P2P_H_ */
