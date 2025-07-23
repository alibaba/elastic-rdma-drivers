// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
 * Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.
 */
#include <linux/vmalloc.h>
#include "sw.h"
#include "sw_loc.h"
#include "sw_queue.h"
#include "../erdma_verbs.h"

int sw_cq_chk_attr(struct sw_dev *sw, struct sw_cq *cq,
		    int cqe, int comp_vector)
{
	int count;

	if (cqe <= 0) {
		pr_warn("cqe(%d) <= 0\n", cqe);
		goto err1;
	}

	if (cqe > sw->attr.max_cqe) {
		pr_warn("cqe(%d) > max_cqe(%d)\n",
			cqe, sw->attr.max_cqe);
		goto err1;
	}

	if (cq) {
		count = queue_count(cq->queue);
		if (cqe < count) {
			pr_warn("cqe(%d) < current # elements in queue (%d)",
				cqe, count);
			goto err1;
		}
	}

	return 0;

err1:
	return -EINVAL;
}

static void sw_send_complete(unsigned long data)
{
	struct sw_cq *cq = (struct sw_cq *)data;
	unsigned long flags;

	spin_lock_irqsave(&cq->cq_lock, flags);
	if (cq->is_dying) {
		spin_unlock_irqrestore(&cq->cq_lock, flags);
		return;
	}
	spin_unlock_irqrestore(&cq->cq_lock, flags);

	cq->master->ibcq.comp_handler(&cq->master->ibcq, cq->master->ibcq.cq_context);
}

int sw_cq_from_init(struct sw_dev *sw, struct sw_cq *cq, int cqe,
		     int comp_vector, struct ib_udata *udata,
		     struct sw_create_cq_resp __user *uresp)
{
	cq->queue = sw_queue_init(sw, &cqe,
				   sizeof(struct sw_cqe));
	if (!cq->queue) {
		pr_warn("unable to create cq\n");
		return -ENOMEM;
	}

	cq->is_dying = false;

	tasklet_init(&cq->comp_task, sw_send_complete, (unsigned long)cq);

	spin_lock_init(&cq->cq_lock);
	cq->ibcq.cqe = cqe;
	return 0;
}

int sw_cq_post(struct sw_cq *cq, struct sw_cqe *cqe, int solicited)
{
	struct ib_event ev;
	unsigned long flags;

	spin_lock_irqsave(&cq->cq_lock, flags);

	if (unlikely(queue_full(cq->queue))) {
		spin_unlock_irqrestore(&cq->cq_lock, flags);
		if (cq->ibcq.event_handler) {
			ev.device = cq->ibcq.device;
			ev.element.cq = &cq->ibcq;
			ev.event = IB_EVENT_CQ_ERR;
			cq->ibcq.event_handler(&ev, cq->ibcq.cq_context);
		}

		return -EBUSY;
	}

	memcpy(producer_addr(cq->queue), cqe, sizeof(*cqe));

	/* make sure all changes to the CQ are written before we update the
	 * producer pointer
	 */
	smp_wmb();

	advance_producer(cq->queue);
	spin_unlock_irqrestore(&cq->cq_lock, flags);

	if ((cq->notify == IB_CQ_NEXT_COMP) ||
	    (cq->notify == IB_CQ_SOLICITED && solicited)) {
		cq->notify = 0;
		tasklet_schedule(&cq->comp_task);
	}

	return 0;
}

void sw_cq_disable(struct sw_cq *cq)
{
	unsigned long flags;

	spin_lock_irqsave(&cq->cq_lock, flags);
	cq->is_dying = true;
	spin_unlock_irqrestore(&cq->cq_lock, flags);
}

void sw_cq_cleanup(struct sw_pool_entry *arg)
{
	struct sw_cq *cq = container_of(arg, typeof(*cq), pelem);

	if (cq->queue)
		sw_queue_cleanup(cq->queue);
}
