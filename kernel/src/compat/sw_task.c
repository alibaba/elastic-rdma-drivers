// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
 * Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.
 */

#include <linux/kernel.h>
#include <linux/interrupt.h>
#include <linux/hardirq.h>

#include "sw_task.h"

int __sw_do_task(struct sw_task *task)

{
	int ret;

	while ((ret = task->func(task->arg)) == 0)
		;

	task->ret = ret;

	return ret;
}

/*
 * this locking is due to a potential race where
 * a second caller finds the task already running
 * but looks just after the last call to func
 */
void sw_do_task(unsigned long data)
{
	int cont;
	int ret;
	unsigned long flags;
	struct sw_task *task = (struct sw_task *)data;

	spin_lock_irqsave(&task->state_lock, flags);
	switch (task->state) {
	case TASK_STATE_START:
		task->state = TASK_STATE_BUSY;
		spin_unlock_irqrestore(&task->state_lock, flags);
		break;

	case TASK_STATE_BUSY:
		task->state = TASK_STATE_ARMED;
#ifdef fallthrough
		fallthrough;
#endif
	case TASK_STATE_ARMED:
		spin_unlock_irqrestore(&task->state_lock, flags);
		return;

	default:
		spin_unlock_irqrestore(&task->state_lock, flags);
		pr_warn("%s failed with bad state %d\n", __func__, task->state);
		return;
	}

	do {
		cont = 0;
		ret = task->func(task->arg);

		spin_lock_irqsave(&task->state_lock, flags);
		switch (task->state) {
		case TASK_STATE_BUSY:
			if (ret)
				task->state = TASK_STATE_START;
			else
				cont = 1;
			break;

		/* soneone tried to run the task since the last time we called
		 * func, so we will call one more time regardless of the
		 * return value
		 */
		case TASK_STATE_ARMED:
			task->state = TASK_STATE_BUSY;
			cont = 1;
			break;

		default:
			pr_warn("%s failed with bad state %d\n", __func__,
				task->state);
		}
		spin_unlock_irqrestore(&task->state_lock, flags);
	} while (cont);

	task->ret = ret;
}

int sw_init_task(void *obj, struct sw_task *task,
		  void *arg, int (*func)(void *), char *name)
{
	task->obj	= obj;
	task->arg	= arg;
	task->func	= func;
	snprintf(task->name, sizeof(task->name), "%s", name);
	task->destroyed	= false;

	tasklet_init(&task->tasklet, sw_do_task, (unsigned long)task);

	task->state = TASK_STATE_START;
	spin_lock_init(&task->state_lock);

	return 0;
}

void sw_cleanup_task(struct sw_task *task)
{
	unsigned long flags;
	bool idle;

	/*
	 * Mark the task, then wait for it to finish. It might be
	 * running in a non-tasklet (direct call) context.
	 */
	task->destroyed = true;

	do {
		spin_lock_irqsave(&task->state_lock, flags);
		idle = (task->state == TASK_STATE_START);
		spin_unlock_irqrestore(&task->state_lock, flags);
	} while (!idle);

	tasklet_kill(&task->tasklet);
}

void sw_run_task(struct sw_task *task, int sched)
{
	if (task->destroyed)
		return;

	if (sched)
		tasklet_schedule(&task->tasklet);
	else
		sw_do_task((unsigned long)task);
}

void sw_disable_task(struct sw_task *task)
{
	tasklet_disable(&task->tasklet);
}

void sw_enable_task(struct sw_task *task)
{
	tasklet_enable(&task->tasklet);
}
