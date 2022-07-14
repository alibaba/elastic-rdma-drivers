// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2020-2022, Alibaba Group.
 * Copyright 2019-2021 Amazon.com, Inc. or its affiliates. All rights reserved.
 */

#include "erdma_p2p.h"
#include "erdma_verbs.h"

static struct mutex p2p_list_lock;
static struct list_head p2p_list;
static atomic64_t next_p2p_ticket;

static const struct erdma_p2p_provider *prov_arr[ERDMA_P2P_PROVIDER_MAX];

/* Register all providers here */
static void p2p_providers_init(void)
{
	prov_arr[ERDMA_P2P_PROVIDER_NVMEM] = nvmem_get_provider();
}

void erdma_p2p_init(void)
{
	mutex_init(&p2p_list_lock);
	INIT_LIST_HEAD(&p2p_list);
	/*
	 * Ideally, first ticket would be zero, but that would make callback
	 * data NULL which is invalid.
	 */
	atomic64_set(&next_p2p_ticket, 1);

	p2p_providers_init();
}

static struct erdma_p2pmem *ticket_to_p2p(u64 ticket)
{
	struct erdma_p2pmem *p2pmem;

	lockdep_assert_held(&p2p_list_lock);
	list_for_each_entry(p2pmem, &p2p_list, list) {
		if (p2pmem->ticket == ticket)
			return p2pmem;
	}

	return NULL;
}

int erdma_p2p_put(u64 ticket, bool in_cb)
{
	struct erdma_p2pmem *p2pmem;
	struct erdma_dev *dev;
	int err;

	mutex_lock(&p2p_list_lock);
	p2pmem = ticket_to_p2p(ticket);
	if (!p2pmem) {
		pr_debug("Ticket %llu not found in the p2pmem list\n", ticket);
		mutex_unlock(&p2p_list_lock);
		return 0;
	}

	dev = p2pmem->dev;
	if (p2pmem->needs_dereg) {
		err = erdma_dereg_mr(p2pmem->ibmr, NULL);
		if (err) {
			mutex_unlock(&p2p_list_lock);
			return err;
		}
		p2pmem->needs_dereg = false;
	}

	list_del(&p2pmem->list);
	mutex_unlock(&p2p_list_lock);
	p2pmem->prov->ops.release(dev, p2pmem, in_cb);

	return 0;
}

struct erdma_p2pmem *erdma_p2p_get(struct erdma_dev *dev, struct erdma_mr *mr, u64 start,
			       u64 length)
{
	const struct erdma_p2p_provider *prov;
	struct erdma_p2pmem *p2pmem;
	u64 ticket;
	int i;

	ticket = atomic64_fetch_inc(&next_p2p_ticket);
	for (i = 0; i < ERDMA_P2P_PROVIDER_MAX; i++) {
		prov = prov_arr[i];
		p2pmem = prov->ops.try_get(dev, ticket, start, length);
		if (p2pmem)
			break;
	}
	if (!p2pmem)
		/* No provider was found, most likely cpu pages */
		return NULL;

	p2pmem->dev = dev;
	p2pmem->ticket = ticket;
	p2pmem->prov = prov;
	mr->p2p_ticket = p2pmem->ticket;

	mutex_lock(&p2p_list_lock);
	list_add(&p2pmem->list, &p2p_list);
	mutex_unlock(&p2p_list_lock);

	return p2pmem;
}

int erdma_p2p_to_page_list(struct erdma_dev *dev, struct erdma_p2pmem *p2pmem,
			 u64 *page_list)
{
	return p2pmem->prov->ops.to_page_list(dev, p2pmem, page_list);
}

unsigned int erdma_p2p_get_page_size(struct erdma_dev *dev,
				   struct erdma_p2pmem *p2pmem)
{
	return p2pmem->prov->ops.get_page_size(dev, p2pmem);
}
